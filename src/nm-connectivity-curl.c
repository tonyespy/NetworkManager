/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2016 Red Hat, Inc.
 *
 */


static size_t
easy_write_callback (void *buffer, size_t size, size_t nmemb, void *userp)
{
	ConCheckCbData *cb_data = userp;

	cb_data->msg = g_realloc (cb_data->msg, cb_data->msg_size + size*nmemb);
	memcpy (cb_data->msg + cb_data->msg_size, buffer, nmemb*size);
	cb_data->msg_size += size * nmemb;

	_LOGT ("Received %lu bytes from CURL\n", size * nmemb);

	return size * nmemb;
}

static NMConnectivityState
curl_check_connectivity (CURLM *mhandle, CURLMcode ret)
{
	NMConnectivity *self;
	NMConnectivityPrivate *priv;
	NMConnectivityState new_state = NM_CONNECTIVITY_UNKNOWN;
	ConCheckCbData *cb_data;
	CURLMsg *msg;
	CURLcode eret;
	gint m_left;

	_LOGT ("curl_multi check for easy messages");
	if (ret != CURLM_OK) {
		_LOGE ("Connectivity check failed");
		return NM_CONNECTIVITY_UNKNOWN;
	}

	while ((msg = curl_multi_info_read(mhandle, &m_left))) {
		_LOGT ("curl MSG received - ehandle:%p, type:%d", msg->easy_handle, msg->msg);
		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Here we have completed a session. Check easy session result. */
		eret = curl_easy_getinfo (msg->easy_handle, CURLINFO_PRIVATE, &cb_data);
		if (eret != CURLE_OK) {
			_LOGE ("curl cannot extract cb_data for easy handle %p, skipping msg", msg->easy_handle);
			continue;
		}
		self = NM_CONNECTIVITY (g_async_result_get_source_object (G_ASYNC_RESULT (cb_data->simple)));
		priv = NM_CONNECTIVITY_GET_PRIVATE (self);

		if (msg->data.result != CURLE_OK) {
			_LOGD ("Check for uri '%s' failed", cb_data->uri);
			new_state = NM_CONNECTIVITY_LIMITED;
			goto cleanup;
		}
		/* TODO --> Check NM specific HTML headers */

		/* Check response */
		if (cb_data->msg && g_str_has_prefix (cb_data->msg, cb_data->response)) {
			_LOGD ("Check for uri '%s' successful.", cb_data->uri);
			new_state = NM_CONNECTIVITY_FULL;
			goto cleanup;
		}

		_LOGI ("Check for uri '%s' did not match expected response '%s'; assuming captive portal.",
			cb_data->uri, cb_data->response);
		new_state = NM_CONNECTIVITY_PORTAL;
cleanup:
		/* Only update the state, if the call was done from external, or if the periodic check
		 * is still the one that called this async check. */
		if (!cb_data->check_id_when_scheduled || cb_data->check_id_when_scheduled == priv->concheck.check_id) {
			/* Only update the state, if the URI and response parameters did not change
			 * since invocation.
			 * The interval does not matter for exernal calls, and for internal calls
			 * we don't reach this line if the interval changed. */
			if (   !g_strcmp0 (cb_data->uri, priv->uri)
			    && !g_strcmp0 (cb_data->response, priv->response)) {
				_LOGT ("Update to connectivity state %s",
				       nm_connectivity_state_to_string (new_state));
				update_state (self, new_state);
			}
		}
		g_simple_async_result_set_op_res_gssize (cb_data->simple, new_state);
		g_simple_async_result_complete (cb_data->simple);
		g_object_unref (cb_data->simple);

		curl_multi_remove_handle (mhandle, cb_data->curl_ehandle);
		curl_easy_cleanup (cb_data->curl_ehandle);
		g_free (cb_data->uri);
		g_free (cb_data->response);
		g_slice_free (ConCheckCbData, cb_data);
	}

	return new_state;
}

static gboolean
curl_timeout_cb (gpointer user_data)
{
	NMConnectivityConcheck *concheck = user_data;
	NMConnectivityState new_state;
	CURLMcode ret;
	int pending_conn;

	ret = curl_multi_socket_action (concheck->curl_mhandle, CURL_SOCKET_TIMEOUT, 0, &pending_conn);
	_LOGT ("timeout elapsed - multi_socket_action (%d conn remaining)", pending_conn);

	new_state = curl_check_connectivity (concheck->curl_mhandle, ret);

	return FALSE;
}

static int
curl_timer_cb (CURLM *multi, long timeout_ms, void *userp)
{
	NMConnectivityConcheck *concheck = userp;

	_LOGT ("curl_multi timer invocation --> timeout ms: %ld", timeout_ms);
	switch (timeout_ms) {
	case -1:
		/* TODO?: should we cancel current timer ? */
		break;
	case 0:
		/*
		 * Do we really need special management of this case?
		 */
	default:
		concheck->curl_timer = g_timeout_add (timeout_ms * 1000, curl_timeout_cb, concheck);
		break;
	}
	return 0;
}

static gboolean
curl_socketevent_cb (GIOChannel *ch, GIOCondition condition, gpointer data)
{
	NMConnectivityConcheck *concheck = data;
	NMConnectivityState new_state;
	CURLMcode ret;
	int pending_conn = 0;
	gboolean bret = TRUE;
	int fd = g_io_channel_unix_get_fd (ch);

	ret = curl_multi_socket_action (concheck->curl_mhandle, fd, 0, &pending_conn);
	_LOGT ("activity on monitored fd %d - multi_socket_action (%d conn remaining)", fd, pending_conn);

	new_state = curl_check_connectivity (concheck->curl_mhandle, ret);

	if (pending_conn == 0) {
		if (concheck->curl_timer)
			g_source_remove (concheck->curl_timer);
		bret = FALSE;
	}
	return bret;
}

static int
curl_socket_cb (CURL *e_handle, curl_socket_t s, int what, void *userp, void *socketp)
{
	NMConnectivityConcheck *concheck = (NMConnectivityConcheck*) userp;
	CurlSockData *fdp = (CurlSockData*) socketp;
	_LOGT ("curl_multi socket callback --> socket %d", s);

	switch (what) {
	case CURL_POLL_NONE:
	case CURL_POLL_IN:
	case CURL_POLL_OUT:
	case CURL_POLL_INOUT:
		if (!fdp) {
			_LOGT ("register new socket s=%d", s);
			fdp = g_malloc0 (sizeof (CurlSockData));
			fdp->ch = g_io_channel_unix_new (s);
			fdp->sockfd = s;
			fdp->action = what;
			fdp->easy = e_handle;
			fdp->ev = g_io_add_watch (fdp->ch, G_IO_IN|G_IO_OUT, curl_socketevent_cb, concheck);
			curl_multi_assign (concheck->curl_mhandle, s, fdp);
		}
		break;
	case CURL_POLL_REMOVE:
		_LOGT ("remove socket s=%d", s);
		if ((fdp) && (fdp->ev)) {
			g_source_remove (fdp->ev);
			g_free (fdp);
		}
		break;
	}
	return 0;
}

/* COMMON */

#define IS_PERIODIC_CHECK(callback)  (callback == run_check_complete)

static void
run_check_complete (GObject      *object,
                    GAsyncResult *result,
                    gpointer      user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	GError *error = NULL;

	nm_connectivity_check_finish (self, result, &error);
	if (error) {
		_LOGE ("check failed: %s", error->message);
		g_error_free (error);
	}
}

static gboolean
run_check (gpointer user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (user_data);

	nm_connectivity_check_async (self, run_check_complete, NULL);
	return TRUE;
}

static gboolean
idle_start_periodic_checks (gpointer user_data)
{
	NMConnectivity *self = user_data;
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	priv->concheck.check_id = g_timeout_add_seconds (priv->interval, run_check, self);
	if (!priv->concheck.initial_check_obsoleted)
		run_check (self);

	return FALSE;
}

static gboolean
nm_connectivity_lib_reschedule (NMConnectivity *self,
                                gboolean force_reschedule,
                                gboolean online,
                                char *uri,
                                guint interval,
                                NMConnectivityConcheck *concheck)
{
	if (online && uri && interval) {
		if (force_reschedule || !concheck->check_id) {
			if (concheck->check_id)
				g_source_remove (concheck->check_id);
			concheck->check_id = g_timeout_add (0, idle_start_periodic_checks, self);
			concheck->initial_check_obsoleted = FALSE;
		}
	} else {
		nm_clear_g_source (&concheck->check_id);
	}

	if (concheck->check_id)
		return TRUE;

	return FALSE;
}


/* CURL specific */
static gboolean
nm_connectivity_do_check (char                   *uri,
                          char                   *response,
                          guint                   interval,
                          GAsyncReadyCallback     callback,
                          GSimpleAsyncResult     *simple,
                          NMConnectivityConcheck *concheck)
{
	if (uri && interval) {
		ConCheckCbData *cb_data = g_slice_new (ConCheckCbData);

		cb_data->curl_ehandle = curl_easy_init ();
		curl_easy_setopt (cb_data->curl_ehandle, CURLOPT_URL, uri);
		curl_easy_setopt (cb_data->curl_ehandle, CURLOPT_WRITEFUNCTION, easy_write_callback);
		curl_easy_setopt (cb_data->curl_ehandle, CURLOPT_WRITEDATA, cb_data);
		curl_easy_setopt (cb_data->curl_ehandle, CURLOPT_PRIVATE, cb_data);
		/*
		 * TODO --> disable keepalive
		 * curl http redirection is disabled by default but not connection presistence
		 */

		cb_data->simple = simple;
		cb_data->uri = g_strdup (uri);
		if (response)
			cb_data->response = g_strdup (response);
		else
			cb_data->response = g_strdup (NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE);
		cb_data->msg_size = 0;
		cb_data->msg = NULL;

		/* For internal calls (periodic), remember the check-id at time of scheduling. */
		cb_data->check_id_when_scheduled = IS_PERIODIC_CHECK (callback) ? concheck->check_id : 0;

		curl_multi_add_handle (concheck->curl_mhandle, cb_data->curl_ehandle);

		concheck->initial_check_obsoleted = TRUE;

		_LOGD ("check: send %srequest to '%s'", IS_PERIODIC_CHECK (callback) ? "periodic " : "", uri);
		return TRUE;
	} else {
		g_warn_if_fail (!IS_PERIODIC_CHECK (callback));
		_LOGD ("check: faking request. Connectivity check disabled");
		return FALSE;
	}
}

static gboolean
nm_connectivity_lib_is_uri_valid (const char *uri, gboolean changed)
{
	gboolean is_valid = TRUE;

	/* Here we should check if url is valid (and return false)
	 * or if the url is an https one (and issue a warning).
	 */
	return is_valid;
}

static void
nm_connectivity_lib_init (NMConnectivityConcheck *concheck, guint timeout)
{
	CURLcode retv;

	retv = curl_global_init (CURL_GLOBAL_ALL);
	if (retv != CURLE_OK)
		 _LOGI ("Unable to init CURL, connectivity check will be affected");

	concheck->curl_mhandle = curl_multi_init ();
	curl_multi_setopt (concheck->curl_mhandle, CURLMOPT_SOCKETFUNCTION, curl_socket_cb);
	curl_multi_setopt (concheck->curl_mhandle, CURLMOPT_SOCKETDATA, concheck);
	curl_multi_setopt (concheck->curl_mhandle, CURLMOPT_TIMERFUNCTION, curl_timer_cb);
	curl_multi_setopt (concheck->curl_mhandle, CURLMOPT_TIMERDATA, concheck);

	/* Manage timeout here */
}

static void
nm_connectivity_lib_dispose (NMConnectivityConcheck *concheck)
{
	/* TODO?: should we check here if there is some pending easy handle? */
	curl_multi_cleanup (concheck->curl_mhandle);
	curl_global_cleanup ();  // not thread safe

	nm_clear_g_source (&concheck->check_id);
}

