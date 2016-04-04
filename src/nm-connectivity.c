/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
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
 * Copyright (C) 2011 Thomas Bechtold <thomasbechtold@jpberlin.de>
 * Copyright (C) 2011 Dan Williams <dcbw@redhat.com>
 */

#include "nm-default.h"

#include <string.h>

#if WITH_CONCHECK
#if WITH_LIBCURL
#include "nm-connectivity-curl.h"
#else
#include "nm-connectivity-soup.h"
#endif
#endif

#include "nm-connectivity.h"
#include "nm-config.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMConnectivity, nm_connectivity, G_TYPE_OBJECT)

#define NM_CONNECTIVITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONNECTIVITY, NMConnectivityPrivate))

#define _NMLOG_DOMAIN  LOGD_CONCHECK
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                "connectivity: " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

typedef struct {
	char *uri;
	char *response;
	guint interval;
	gboolean online; /* whether periodic connectivity checking is enabled. */

#if WITH_CONCHECK
	NMConnectivityConcheck concheck;
#endif

	NMConnectivityState state;
} NMConnectivityPrivate;

enum {
	PROP_0,
	PROP_URI,
	PROP_INTERVAL,
	PROP_RESPONSE,
	PROP_STATE,
	LAST_PROP
};

NMConnectivityState
nm_connectivity_get_state (NMConnectivity *connectivity)
{
	g_return_val_if_fail (NM_IS_CONNECTIVITY (connectivity), NM_CONNECTIVITY_UNKNOWN);

	return NM_CONNECTIVITY_GET_PRIVATE (connectivity)->state;
}

NM_UTILS_LOOKUP_STR_DEFINE (nm_connectivity_state_to_string, NMConnectivityState,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("???"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_UNKNOWN,  "UNKNOWN"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_NONE,     "NONE"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_LIMITED,  "LIMITED"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_PORTAL,   "PORTAL"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_FULL,     "FULL"),
);

static void
update_state (NMConnectivity *self, NMConnectivityState state)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (priv->state != state) {
		_LOGD ("state changed from %s to %s",
		       nm_connectivity_state_to_string (priv->state),
		       nm_connectivity_state_to_string (state));
		priv->state = state;
		g_object_notify (G_OBJECT (self), NM_CONNECTIVITY_STATE);
	}
}

#if WITH_CONCHECK
#if WITH_LIBCURL
#include "nm-connectivity-curl.c"
#else
#include "nm-connectivity-soup.c"
#endif
#endif

static void
_reschedule_periodic_checks (NMConnectivity *self, gboolean force_reschedule)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

#if WITH_CONCHECK
	if (nm_connectivity_lib_reschedule (self, force_reschedule, priv->online,
	                                    priv->uri, priv->interval, &priv->concheck))
		return;
#endif

	/* Either @online is %TRUE but we aren't checking connectivity, or
	 * @online is %FALSE. Either way we can update our status immediately.
	 */
	update_state (self, priv->online ? NM_CONNECTIVITY_FULL : NM_CONNECTIVITY_NONE);
}

void
nm_connectivity_set_online (NMConnectivity *self,
                            gboolean        online)
{
	NMConnectivityPrivate *priv= NM_CONNECTIVITY_GET_PRIVATE (self);

	online = !!online;
	if (priv->online != online) {
		_LOGD ("set %s", online ? "online" : "offline");
		priv->online = online;
		_reschedule_periodic_checks (self, FALSE);
	}
}

void
nm_connectivity_check_async (NMConnectivity      *self,
                             GAsyncReadyCallback  callback,
                             gpointer             user_data)
{
	NMConnectivityPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_CONNECTIVITY (self));
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	simple = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                    nm_connectivity_check_async);

#if WITH_CONCHECK
	if (nm_connectivity_do_check (priv->uri, priv->response, priv->interval,
	                              callback, simple, &(priv->concheck)))
		return;
#else
	_LOGD ("check: faking request. Compiled without connectivity-check support");
#endif

	g_simple_async_result_set_op_res_gssize (simple, priv->state);
	g_simple_async_result_complete_in_idle (simple);
	g_object_unref (simple);
}

NMConnectivityState
nm_connectivity_check_finish (NMConnectivity  *self,
                              GAsyncResult    *result,
                              GError         **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self), nm_connectivity_check_async), NM_CONNECTIVITY_UNKNOWN);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NM_CONNECTIVITY_UNKNOWN;
	return (NMConnectivityState) g_simple_async_result_get_op_res_gssize (simple);
}

/**************************************************************************/

NMConnectivity *
nm_connectivity_new (const char *uri,
                     guint interval,
                     const char *response)
{
	return g_object_new (NM_TYPE_CONNECTIVITY,
	                     NM_CONNECTIVITY_URI, uri,
	                     NM_CONNECTIVITY_INTERVAL, interval,
	                     NM_CONNECTIVITY_RESPONSE, response,
	                     NULL);
}

static void
set_property (GObject *object, guint property_id,
              const GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	const char *uri, *response;
	guint interval;
	gboolean changed;

	switch (property_id) {
	case PROP_URI:
		uri = g_value_get_string (value);
		if (uri && !*uri)
			uri = NULL;
		changed = g_strcmp0 (uri, priv->uri) != 0;
#if WITH_CONCHECK
		if (uri) {
			if (!nm_connectivity_lib_is_uri_valid(uri, changed))
				uri = NULL;
		}
#endif
		if (changed) {
			g_free (priv->uri);
			priv->uri = g_strdup (uri);
			_reschedule_periodic_checks (self, TRUE);
		}
		break;
	case PROP_INTERVAL:
		interval = g_value_get_uint (value);
		if (priv->interval != interval) {
			priv->interval = interval;
			_reschedule_periodic_checks (self, TRUE);
		}
		break;
	case PROP_RESPONSE:
		response = g_value_get_string (value);
		if (g_strcmp0 (response, priv->response) != 0) {
			/* a response %NULL means, NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE. Any other response
			 * (including "") is accepted. */
			g_free (priv->response);
			priv->response = g_strdup (response);
			_reschedule_periodic_checks (self, TRUE);
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint property_id,
              GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	switch (property_id) {
	case PROP_URI:
		g_value_set_string (value, priv->uri);
		break;
	case PROP_INTERVAL:
		g_value_set_uint (value, priv->interval);
		break;
	case PROP_RESPONSE:
		if (priv->response)
			g_value_set_string (value, priv->response);
		else
			g_value_set_static_string (value, NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE);
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}


static void
nm_connectivity_init (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

#if WITH_CONCHECK
	nm_connectivity_lib_init (&priv->concheck, 15);
#endif
	priv->state = NM_CONNECTIVITY_NONE;
}


static void
dispose (GObject *object)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	g_clear_pointer (&priv->uri, g_free);
	g_clear_pointer (&priv->response, g_free);

#if WITH_CONCHECK
	nm_connectivity_lib_dispose (&priv->concheck);
#endif

	G_OBJECT_CLASS (nm_connectivity_parent_class)->dispose (object);
}


static void
nm_connectivity_class_init (NMConnectivityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	g_type_class_add_private (klass, sizeof (NMConnectivityPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
	g_object_class_install_property
	    (object_class, PROP_URI,
	     g_param_spec_string (NM_CONNECTIVITY_URI, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_INTERVAL,
	     g_param_spec_uint (NM_CONNECTIVITY_INTERVAL, "", "",
	                        0, G_MAXUINT, NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT |
	                        G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_RESPONSE,
	     g_param_spec_string (NM_CONNECTIVITY_RESPONSE, "", "",
	                          NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_STATE,
	     g_param_spec_uint (NM_CONNECTIVITY_STATE, "", "",
	                        NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS));
}

