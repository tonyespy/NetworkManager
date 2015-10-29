/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* Ofono modem settings service
 *
 * Mathieu Trudel-Lapierre <mathieu-tl@ubuntu.com>
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
 * (C) Copyright 2013 Canonical Ltd.
 */

#include <string.h>

#include <net/ethernet.h>
#include <netinet/ether.h>

#include <gmodule.h>
#include <glib-object.h>
#include <glib/gi18n.h>
#include <glib.h>
#include <gio/gio.h>
#include <nm-setting-connection.h>

#include "nm-core-internal.h"
#include "nm-system-config-interface.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-wireless.h"
#include "nm-setting-wired.h"
#include "nm-setting-ppp.h"
#include "nm-utils.h"

#include "nm-ofono-connection.h"
#include "plugin.h"
#include "parser.h"
#include "nm-inotify-helper.h"

#include "nm-logging.h"

#include <arpa/inet.h>

#define OFONO_CONFIG_DIR "/var/lib/ofono"

#define OFONO_PLUGIN_NAME "ofono"
#define OFONO_PLUGIN_INFO "(C) 2013 Canonical Ltd.  To report bugs please use the NetworkManager mailing list."

#define OFONO_KEY_FILE_GROUP "settings"

typedef struct {
	GHashTable *connections;  /* NMOfonoConnection */

	GFileMonitor *ofono_dir_monitor;
	gulong ofono_dir_monitor_id;

	GHashTable *ofono_imsi_monitors;
	GHashTable *ofono_imsi_monitor_ids;
} SCPluginOfonoPrivate;


static gboolean nm_ofono_read_imsi_contexts (SCPluginOfono *self,
                                             const char *imsi,
                                             GError **error);

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginOfono, sc_plugin_ofono, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
                                               system_config_interface_init))

#define SC_PLUGIN_OFONO_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_OFONO, SCPluginOfonoPrivate))

GQuark
ofono_plugin_error_quark (void)
{
        static GQuark error_quark = 0;

	if (!error_quark) {
		error_quark = g_quark_from_static_string ("ofono-plugin-error-quark");
	}

	return error_quark;
}

static void
ignore_cb ()
{
}

static void
SCPluginOfono_parse_contexts (SCPluginOfono *self, GSList *contexts, const char *imsi)
{
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (self);
	GSList *list;
	GList *keys;
	NMOfonoConnection *exported;
	gboolean found = FALSE;
	char *uuid;
	GHashTableIter iter;
	gpointer key;
	GHashTable *uuids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	for (list = contexts; list; list = list->next) {
		GHashTable *context = (GHashTable *) list->data;
		const char *id, *name;
		char *idstr;

		id = g_hash_table_lookup (context, "ID");
		name = g_hash_table_lookup (context, "Name");

		idstr = g_strconcat ("/", imsi, "/", id, NULL);
		uuid = nm_utils_uuid_generate_from_string (idstr, -1,
		                                           NM_UTILS_UUID_TYPE_LEGACY,
		                                           NULL);
		g_free (idstr);

		g_hash_table_insert (uuids, g_strdup (uuid), NULL);

		nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: found internet context '%s' (%s)",
		             name, id);

		/* Ignore any connection for this block that was previously found */
		exported = g_hash_table_lookup (priv->connections, uuid);
		if (exported) {
			nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: context '%s' (%s) already exported",
			             name, id);
			goto next_context;
		}

		/* add the new connection */
		exported = nm_ofono_connection_new (context);
		nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: adding %s (%s) to connections", name, uuid);

		/* FIXME: investigate if it's possible to set directly via g_object_* method...  */
		/* Lower disabled timer to 30s */
		nm_settings_connection_set_reset_retries_timeout (NM_SETTINGS_CONNECTION (exported), 30);

		g_hash_table_insert (priv->connections, g_strdup (uuid), exported);
		g_signal_emit_by_name (self, NM_SYSTEM_CONFIG_INTERFACE_CONNECTION_ADDED, exported);

next_context:
		g_free (uuid);
	}

	/*
	 * Remove any connections that have the same IMSI
	 * as our current list of contexts *and* are not
	 * present in our current list ( ie. the context
	 * has been deleted ).
	 *
	 * TODO: note, could this be handled directly by
	 * the imsi_monitor???  If so, it gets rid of
	 * this loop.  Doing so would require caching
	 * the preferred contexts for each IMSI
	 */
	g_hash_table_iter_init (&iter, priv->connections);

	while (g_hash_table_iter_next (&iter, &key, NULL)) {
		char **context_id;
		const char *idstr;

		uuid = (char *) key;

		found = g_hash_table_lookup_extended (uuids, uuid, NULL, NULL);
		if (!found) {
			exported = g_hash_table_lookup (priv->connections, uuid);
			idstr = nm_connection_get_id (NM_CONNECTION (exported));
			context_id = g_strsplit (idstr, "/", 0);
			g_assert (context_id[2]);

			if (g_strcmp0(imsi, context_id[1]) == 0) {

				nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: removing (%s) from connections", idstr);

				nm_settings_connection_signal_remove (NM_SETTINGS_CONNECTION (exported));
				g_hash_table_remove (priv->connections, uuid);
			}

			g_strfreev (context_id);
		}
	}

	if (keys)
		g_list_free (keys);

	if (uuids)
		g_hash_table_destroy (uuids);
}

static gboolean
nm_ofono_read_imsi_contexts (SCPluginOfono *self, const char *imsi, GError **error)
{
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (self);
	GHashTable *context;
	GHashTable *pref_context = NULL;
	GSList *contexts = NULL;
	GDir *imsi_dir;
	const char *file;
	gchar **groups;
	gchar **keys, *imsi_path, *file_path;
	gboolean res;
	GKeyFile *keyfile = NULL;
	GError *tmp_error = NULL;

	imsi_path = g_strdup_printf (OFONO_CONFIG_DIR "/%s", imsi);
	imsi_dir = g_dir_open (imsi_path, 0, NULL);

	nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: reading configuration for IMSI %s", imsi);
	while (imsi_dir && (file = g_dir_read_name (imsi_dir)) != NULL) {
		int i, j;

		if (tmp_error)
			g_clear_error (&tmp_error);

		/* Skip files not named "gprs" */
		if (!!g_strcmp0 (file, "gprs"))
			continue;

		keyfile = g_key_file_new ();
		file_path = g_strdup_printf ("%s/%s", imsi_path, file);
		res = g_key_file_load_from_file (keyfile, file_path, G_KEY_FILE_NONE, &tmp_error);
		g_free (file_path);

		if (!res) {
			nm_log_warn (LOGD_SETTINGS, "SCPlugin-Ofono: error reading %s: %s",
			             imsi,
			             tmp_error && tmp_error->message ? tmp_error->message : "(unknown)");
			continue;
		}

		groups = g_key_file_get_groups (keyfile, NULL);
		for (i = 0; groups[i]; i++) {
			if (!g_strrstr (groups[i], "context"))
				continue;

			g_clear_error (&tmp_error);
			keys = g_key_file_get_keys (keyfile, groups[i], NULL, &tmp_error);
			if (tmp_error) {
				continue;
			}

			context = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
			g_hash_table_insert (context, "ID", g_strdup (groups[i]));
			g_hash_table_insert (context, "IMSI", g_strdup (imsi));

			for (j = 0; keys[j]; j++) {
				gchar *prop_value;

				prop_value = g_key_file_get_string (keyfile, groups[i], keys[j], NULL);

				/*
				 * FIXME: if file notify fires multiple times when 'pref' is updated,
				 * need someway to cache the new 'Pref' value, so subequent file changes
				 * are just ignored if 'Pref' hasn't changed...
				 *
				 * Note, when 'Preferred' gets set to 'true', this also causes the
				 * 'Settings' and 'Active' properties to be updated, which triggers
				 * the imsi_monitor and causes this function to be called also.
				 */

				if (!strcmp (keys[j], "Type") && strcmp (prop_value, "internet")) {

					g_hash_table_destroy (context);
					g_free (prop_value);

					goto next_context;
				}

				/* If more than one context is 'Preferred', first one wins... */
				if (!strcmp (keys[j], "Preferred") && !strcmp (prop_value, "true")) {
					nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: '%s' - Preferred = 'true'", groups[i]);

					pref_context = context;
				}

				if (!strcmp (keys[j], "Name"))
					g_hash_table_insert (context, "Name", prop_value);
			}

			if (pref_context != NULL) {
				/*
				 * Preferred context found, free any contexts created
				 * before the preferred context was found.
				 */

				if (contexts) {
					g_slist_free_full (contexts, (GDestroyNotify) g_hash_table_destroy);
					contexts = NULL;
				}

				contexts = g_slist_append (contexts, pref_context);
				break;
			} else
				contexts = g_slist_append (contexts, context);
next_context:
			if (keys)
				g_strfreev (keys);
		}

		g_key_file_free (keyfile);
		g_strfreev (groups);
	}

	g_free (imsi_path);

	if (imsi_dir)
		g_dir_close (imsi_dir);

	SCPluginOfono_parse_contexts (self, contexts, imsi);

	if (contexts) {
		g_slist_free_full (contexts, (GDestroyNotify) g_hash_table_destroy);
		contexts = NULL;
		g_clear_error (&tmp_error);
		return TRUE;
	}

	if (tmp_error) {
		g_propagate_error (error, tmp_error);
		g_clear_error (&tmp_error);
	}
	else {
		g_set_error (error,
		             ofono_plugin_error_quark (),
                             0,
		             "No contexts were found.");
	}

	return FALSE;
}

static gboolean
SCPluginOfono_should_ignore_imsi (const char *imsi)
{
	/* Ignore paths that are not IMSI */
	if (g_strcmp0 (imsi, "ofono") == 0)
		return TRUE;

	/* Ignore IMSI paths with dashes */
	if (g_strrstr (imsi, "-") != NULL)
		return TRUE;

	return FALSE;
}

static void
ofono_imsi_changed (GFileMonitor *monitor,
                   GFile *file,
                   GFile *other_file,
                   GFileMonitorEvent event_type,
                   gpointer user_data)
{
	SCPluginOfono *self = SC_PLUGIN_OFONO (user_data);
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (self);
	GFile *parent;
	gchar *path, *imsi;
	GError *error = NULL;

	path = g_file_get_path (file);

	/* If this isn't about a "gprs" file we don't want to know */
	if (g_strrstr (path, "gprs") == NULL)
		goto out_imsi;

	switch (event_type) {
		case G_FILE_MONITOR_EVENT_DELETED:
			nm_log_info (LOGD_SETTINGS, "SCPluginOfono: %s got removed.", path);
			break;
		case G_FILE_MONITOR_EVENT_CREATED:
		case G_FILE_MONITOR_EVENT_CHANGED:
		case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
			parent = g_file_get_parent (file);
			imsi = g_file_get_basename (parent);

			if (!nm_ofono_read_imsi_contexts (self, imsi, &error)) {
				nm_log_warn (LOGD_SETTINGS, "SCPluginOfono: an error occured while reading "
				             "contexts for IMSI %s", imsi);
			}

			g_object_unref (parent);
			g_free (imsi);
			break;
		default:
			nm_log_warn (LOGD_SETTINGS, "SCPluginOfono: unexpected event type '%d'", (int) event_type);
			break;
	}

out_imsi:
	g_free (path);

	return;
}

static gboolean
add_gprs_file_watch(SCPluginOfono *self, const char *imsi)
{

	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (self);
	gchar *path;
	GFile *config_path;
	GFileMonitor *imsi_monitor;
	gulong id;
	const char *id_str;
	gboolean result = FALSE;

	id_str = g_hash_table_lookup (priv->ofono_imsi_monitor_ids, imsi);
	if (id_str != NULL) {
		nm_log_warn (LOGD_SETTINGS, "SCPluginOfono: file_monitor already exists for %s", imsi);
		goto done;
	}

	path = g_strdup_printf (OFONO_CONFIG_DIR "/%s", imsi);

	/*
	 * TODO: an optimiztion woudld be to add only monitor the directory
	 * if /<IMSI>/gprs doesn't yet exist.  Otherwise, a regular file
	 * monitor could be used, cutting down the times NM gets notified
	 * for changes to other ofono settings files...
	 */

	config_path = g_file_new_for_path (path);
	imsi_monitor = g_file_monitor_directory (config_path,
	                                         G_FILE_MONITOR_NONE,
	                                         NULL, NULL);

	g_object_unref (config_path);
	g_free (path);

	if (imsi_monitor) {
		nm_log_info (LOGD_SETTINGS, "SCPluginOfono: watching file changes for %s", imsi);
		id = g_signal_connect (imsi_monitor, "changed",
		                       G_CALLBACK (ofono_imsi_changed),
		                       self);
		g_hash_table_insert (priv->ofono_imsi_monitors,
		                     g_strdup (imsi),
		                     g_object_ref (imsi_monitor));
		g_hash_table_insert (priv->ofono_imsi_monitor_ids,
		                     g_strdup (imsi),
		                     (gpointer) id);
		g_object_unref (imsi_monitor);

		result = TRUE;
	} else {
		nm_log_warn (LOGD_SETTINGS, "SCPluginOfono: couldn't create file monitor for %s.", imsi);
	}

done:
	return result;
}

static void
ofono_dir_changed (GFileMonitor *monitor,
                   GFile *file,
                   GFile *other_file,
                   GFileMonitorEvent event_type,
                   gpointer user_data)
{
	SCPluginOfono *self = SC_PLUGIN_OFONO (user_data);
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (self);
	GFileMonitor *imsi_monitor;
	GFile *config_path;
	gulong id;
	gchar *imsi, *path;
	gboolean res;
	GError *error = NULL;

	imsi = g_file_get_basename (file);

	if (SCPluginOfono_should_ignore_imsi (imsi))
		goto out_ofono;

	switch (event_type) {
		case G_FILE_MONITOR_EVENT_DELETED:
			nm_log_info (LOGD_SETTINGS, "SCPluginOfono: removed %s.", imsi);

			/* Disable and remove the monitor, since the directory was deleted */
			imsi_monitor = g_hash_table_lookup (priv->ofono_imsi_monitors, imsi);
			id = (gulong) g_hash_table_lookup (priv->ofono_imsi_monitor_ids, imsi);

			if (imsi_monitor) {
				if (id)
					g_signal_handler_disconnect (imsi_monitor, id);

				g_file_monitor_cancel (imsi_monitor);
				g_hash_table_remove (priv->ofono_imsi_monitors, imsi);
			}

			break;
		case G_FILE_MONITOR_EVENT_CREATED:
		case G_FILE_MONITOR_EVENT_CHANGED:
		case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:

			/* TODO: is this a valid test?  If only new dirs and/or files created in
			 * the config dir ( /var/lib/ofono ), and not it's sub-dirs, then if
			 * there's no trailing slash, then it's a new IMSI directory.  Also
			 * determine if writes to gprs files cause CHANGE events in the top-level
			 * dir.... */

			/* Add watches for the IMSI directories too */
			if ((g_strrstr (imsi, "gprs") == NULL) && add_gprs_file_watch (self, imsi)) {

					res = nm_ofono_read_imsi_contexts (self, imsi, &error);
					if (!res)
						nm_log_warn (LOGD_SETTINGS, "SCPluginOfono: an error occured while reading "
				        		     "contexts for IMSI %s", imsi);
			}

		default:
			break;
	}

out_ofono:
	g_free (imsi);

	return;
}

static void
SCPluginOfono_read_context_files (SCPluginOfono *self)
{
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (self);
	GDir *config;
	GFile *config_path;
	GFileMonitor *monitor;
	const char *imsi;
	gboolean res = FALSE;
	GError *error = NULL;

	/* Hook up a GFileMonitor to watch for new context directories being created.
	 * This is in case ofono's provisioning plugin hasn't run when NM and the
	 * ofono settings plugin are started, and to pick up new created contexts.
	 */
	config_path = g_file_new_for_path (OFONO_CONFIG_DIR);
	if (g_file_query_exists (config_path, NULL)) {

		monitor = g_file_monitor_directory (config_path, G_FILE_MONITOR_NONE,
		                                    NULL, NULL);

		if (monitor) {
			priv->ofono_dir_monitor = monitor;
		} else {
			nm_log_warn (LOGD_SETTINGS, "SCPlugin-Ofono: couldn't create dir monitor");
			goto done;
		}
	} else {
		nm_log_warn (LOGD_SETTINGS, "SCPlugin-Ofono: file doesn't exist: /var/lib/ofono");
		goto done;
		return;
 	}

	config = g_dir_open (OFONO_CONFIG_DIR, 0, NULL);
	while ((imsi = g_dir_read_name (config)) != NULL) {

		if (SCPluginOfono_should_ignore_imsi (imsi))
			continue;

		res = nm_ofono_read_imsi_contexts (self, imsi, &error);

		if (error && error->message)
			nm_log_warn (LOGD_SETTINGS, "SCPlugin-Ofono: %s", error->message);

		/* TODO: could go into read_imsi_contexts? */
		add_gprs_file_watch(self, imsi);
	}

	priv->ofono_dir_monitor_id = g_signal_connect (monitor, "changed",
	                                               G_CALLBACK (ofono_dir_changed), self);
done:
	g_object_unref (config_path);
}

/* ---------------------------------------------------------------------- */

static void
sc_plugin_ofono_class_init (SCPluginOfonoClass *req_class);

static void
SCPluginOfono_init (NMSystemConfigInterface *config);

static GSList *
SCPluginOfono_get_unmanaged_specs (NMSystemConfigInterface * config);

/* Returns the plugins currently known list of connections.  The returned
 * list is freed by the system settings service.
 */
static GSList*
SCPluginOfono_get_connections (NMSystemConfigInterface *config);

static void
GObject__get_property (GObject *object, guint prop_id,
				   GValue *value, GParamSpec *pspec)
{
	NMSystemConfigInterface *self = NM_SYSTEM_CONFIG_INTERFACE (object);

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, OFONO_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, OFONO_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, 0);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, "");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
GObject__set_property (GObject *object, guint prop_id,
				   const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*  GObject */
static void
dispose (GObject *object);

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	system_config_interface_class->init = SCPluginOfono_init;
	system_config_interface_class->get_connections = SCPluginOfono_get_connections;
	system_config_interface_class->get_unmanaged_specs = SCPluginOfono_get_unmanaged_specs;
}

static void
sc_plugin_ofono_class_init (SCPluginOfonoClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginOfonoPrivate));

	object_class->dispose = dispose;
	object_class->get_property = GObject__get_property;
	object_class->set_property = GObject__set_property;

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_NAME);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
	                                  NM_SYSTEM_CONFIG_INTERFACE_INFO);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
	                                  NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES);

	g_object_class_override_property (object_class,
	                                  NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
	                                  NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
SCPluginOfono_init (NMSystemConfigInterface *config)
{
	SCPluginOfono *self = SC_PLUGIN_OFONO (config);
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (self);
	GError *error = NULL;
	gboolean success = FALSE;

	/* Keep a hash table of GFileMonitors per IMSI for later removal */
	if (!priv->ofono_imsi_monitors)
		priv->ofono_imsi_monitors = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	if (!priv->ofono_imsi_monitor_ids)
		priv->ofono_imsi_monitor_ids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	if(!priv->connections)
		priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: init!");

	SCPluginOfono_read_context_files (self);

	nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: end _init.");
}

static GSList *
SCPluginOfono_get_unmanaged_specs (NMSystemConfigInterface * config)
{
	return NULL;
}

static gint
sort_by_context_id (gconstpointer a, gconstpointer b)
{
	g_return_val_if_fail (a != NULL, 0);
	g_return_val_if_fail (b != NULL, 0);

	const char *context_a = nm_connection_get_id (NM_CONNECTION (a));
	const char *context_b = nm_connection_get_id (NM_CONNECTION (b));

	return g_strcmp0 (context_a, context_b);
}

/* Returns the plugins currently known list of connections.  The returned
 * list is freed by the system settings service.
 */
static GSList*
SCPluginOfono_get_connections (NMSystemConfigInterface *config)
{
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (config);
	GSList *connections = NULL;
	GHashTableIter iter;
	gpointer value;

	nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: (%d) ... get_connections.", GPOINTER_TO_UINT(config));

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		connections = g_slist_prepend (connections, value);

	connections = g_slist_sort (connections, sort_by_context_id);

	nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: (%d) connections count: %d", GPOINTER_TO_UINT(config), g_slist_length(connections));
	return connections;
}

static void
sc_plugin_ofono_init (SCPluginOfono *plugin)
{
}

static void
cancel_monitor (gpointer key, gpointer value, gpointer user_data)
{
	GHashTable *monitor_ids = user_data;
	GFileMonitor *monitor = (GFileMonitor *) value;
	gchar *imsi = (gchar *) key;
	gulong id;

	if (monitor_ids) {
		id = (gulong) g_hash_table_lookup (monitor_ids, imsi);
		g_signal_handler_disconnect (monitor, id);
	}

	g_file_monitor_cancel (monitor);

	return;
}

static void
dispose (GObject *object)
{
	SCPluginOfono *plugin = SC_PLUGIN_OFONO (object);
	SCPluginOfonoPrivate *priv = SC_PLUGIN_OFONO_GET_PRIVATE (plugin);

	if (priv->ofono_dir_monitor) {
		if (priv->ofono_dir_monitor_id)
			g_signal_handler_disconnect (priv->ofono_dir_monitor,
			                             priv->ofono_dir_monitor_id);

		g_file_monitor_cancel (priv->ofono_dir_monitor);
		g_object_unref (priv->ofono_dir_monitor);
		priv->ofono_dir_monitor = NULL;
	}

	if (priv->ofono_imsi_monitors) {
		g_hash_table_foreach (priv->ofono_imsi_monitors, cancel_monitor, priv->ofono_imsi_monitor_ids);

		g_hash_table_destroy (priv->ofono_imsi_monitors);
		priv->ofono_imsi_monitors = NULL;

		if (priv->ofono_imsi_monitor_ids) {
			g_hash_table_destroy (priv->ofono_imsi_monitor_ids);
			priv->ofono_imsi_monitor_ids = NULL;
		}
	}

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	G_OBJECT_CLASS (sc_plugin_ofono_parent_class)->dispose (object);
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginOfono *singleton = NULL;
	SCPluginOfonoPrivate *priv;

	if (!singleton) {
		singleton = SC_PLUGIN_OFONO (g_object_new (SC_TYPE_PLUGIN_OFONO, NULL));
		if (singleton) {
			priv = SC_PLUGIN_OFONO_GET_PRIVATE (singleton);
		}
	} else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}

