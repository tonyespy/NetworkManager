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
 * Copyright (C) 2013 Canonical Ltd.
 */

#include "config.h"

#include <string.h>
#include <glib/gi18n.h>

#include "nm-dbus-glib-types.h"
#include "nm-modem-ofono.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-gsm.h"
#include "nm-settings-connection.h"
#include "nm-enum-types.h"
#include "nm-logging.h"
#include "nm-modem.h"
#include "nm-dbus-manager.h"
#include "nm-platform.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMModemOfono, nm_modem_ofono, NM_TYPE_MODEM)

#define NM_MODEM_OFONO_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_OFONO, NMModemOfonoPrivate))

typedef struct {
	GHashTable *connect_properties;

	NMDBusManager *dbus_mgr;

	DBusGProxy *modem_proxy;
	DBusGProxy *connman_proxy;
	DBusGProxy *context_proxy;
	DBusGProxy *simmanager_proxy;

	GError *property_error;

	char **interfaces;
	char *context_path;
	char *imsi;

	gboolean modem_online;
	gboolean gprs_attached;

	NMIP4Config *ip4_config;

} NMModemOfonoPrivate;

static gboolean
ip_string_to_network_address (const gchar *str,
                              guint32 *out)
{
	guint32 addr = 0;
	gboolean success = FALSE;

	if (!str || inet_pton (AF_INET, str, &addr) != 1)
		addr = 0;
	else
		success = TRUE;

	*out = (guint32)addr;
	return success;
}

static void
update_modem_state (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMModemState state = nm_modem_get_state (NM_MODEM (self));
	NMModemState new_state = NM_MODEM_STATE_UNKNOWN;
	const char *reason = NULL;

	nm_log_info (LOGD_MB, "(%s): %s: 'Attached': %s 'Online': %s 'IMSI': %s",
	             nm_modem_get_path (NM_MODEM (self)),
	             __func__,
	             priv->gprs_attached ? "true" : "false",
	             priv->modem_online ? "true" : "false",
	             priv->imsi);

	if (priv->modem_online == FALSE) {
		new_state = NM_MODEM_STATE_DISABLED;
		reason = "modem 'Online=false'";
	} else if (priv->imsi == NULL && state != NM_MODEM_STATE_ENABLING) {
		new_state = NM_MODEM_STATE_DISABLED;
		reason = "modem not ready";
	} else if (priv->gprs_attached == FALSE) {
		if (state >= NM_MODEM_STATE_ENABLING) {
			new_state = NM_MODEM_STATE_SEARCHING;
			reason = "modem searching";
		}
	} else {
		new_state = NM_MODEM_STATE_REGISTERED;
		reason = "modem ready";
	}

	if (state != new_state)
		nm_modem_set_state (NM_MODEM (self), new_state, reason);
}

/* Disconnect stuff */
typedef struct {
	NMModemOfono *self;
	gboolean warn;
} SimpleDisconnectContext;

static gboolean
disconnect_finish (NMModem *self,
                   GAsyncResult *res,
                   GError **error)
{
	/* FIXME: might actually be wrong, copied straight from NMModemBroadband.
	 * this is already working using GDBusProxy, so won't be called until the
	 * rest of this file is ported: uncomment when everything else is ported.
	 */
	//return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error);
	return FALSE;
}

static void
simple_disconnect_context_free (SimpleDisconnectContext *ctx)
{
	g_object_unref (ctx->self);
	g_slice_free (SimpleDisconnectContext, ctx);
}

static void
disconnect_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	SimpleDisconnectContext *ctx = (SimpleDisconnectContext*) user_data;
	NMModemOfono *self = ctx->self;
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID)) {
		if (ctx->warn)
			nm_log_warn (LOGD_MB, "(%s) failed to disconnect modem: %s",
			             nm_modem_get_uid (NM_MODEM (self)),
			             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	update_modem_state (self);

	simple_disconnect_context_free (ctx);
}

static void
disconnect (NMModem *self,
            gboolean warn,
            GCancellable *cancellable,
            GAsyncReadyCallback callback,
            gpointer user_data)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	SimpleDisconnectContext *ctx;
	GValue value = G_VALUE_INIT;
	NMModemState state = nm_modem_get_state (NM_MODEM (self));

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (state != NM_MODEM_STATE_CONNECTED)
		return;

	ctx = g_slice_new (SimpleDisconnectContext);
	ctx->self = g_object_ref (self);
	ctx->warn = warn;

	nm_modem_set_state (NM_MODEM (self),
	                    NM_MODEM_STATE_DISCONNECTING,
	                    nm_modem_state_to_string (NM_MODEM_STATE_DISCONNECTING));

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, FALSE);

	dbus_g_proxy_begin_call_with_timeout (priv->context_proxy,
	                                      "SetProperty", disconnect_done,
	                                      ctx, NULL, 20000,
	                                      G_TYPE_STRING, "Active",
	                                      G_TYPE_VALUE, &value,
	                                      G_TYPE_INVALID);
}

static void
deactivate_cleanup (NMModem *_self, NMDevice *device)
{
	/* NMModemOfono *self = NM_MODEM_OFONO (_self); */

	/* TODO: cancel SimpleConnect() if any */

	/* TODO: Cleanup IPv4 addresses and routes */
	/*
	g_clear_object (&self->priv->ipv4_config);
	g_clear_object (&self->priv->ipv6_config);
	*/

	/*
	self->priv->pin_tries = 0;
	*/

	/* Chain up parent's */
	NM_MODEM_CLASS (nm_modem_ofono_parent_class)->deactivate_cleanup (_self, device);
}

static DBusGProxy *
get_ofono_proxy (NMModemOfono *self, const char *path, const char *interface)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	DBusGConnection *bus;
	DBusGProxy *proxy;

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);

	proxy = dbus_g_proxy_new_for_name (bus,
	                                   OFONO_DBUS_SERVICE,
	                                   path,
	                                   interface);

	return proxy;
}
static void
handle_attached (NMModemOfono *self, GValue *value)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	gboolean attached = g_value_get_boolean (value);

	if (priv->gprs_attached != attached) {
		priv->gprs_attached = attached;

		nm_log_info (LOGD_MB, "(%s): %s: new value for 'Attached': %s",
		             nm_modem_get_path (NM_MODEM (self)),
		             __func__,
		             attached ? "true" : "false");

		update_modem_state (self);
	}
}


static void
get_ofono_conn_manager_properties_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	GError *error = NULL;
	GHashTable *properties = NULL;
	GValue *value = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
		                        DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
		                        G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed get connection manager properties: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		goto done;
	}

	value = g_hash_table_lookup (properties, "Attached");
	if (value) {
		handle_attached (self, value);
		g_value_unset (value);
	} else
		nm_log_warn (LOGD_MB, "(%s): %s: no 'Attached' property found",
		             nm_modem_get_path (NM_MODEM (self)),
		             __func__);

done:
	g_object_unref (self);
}

static void
ofono_conn_properties_changed (DBusGProxy *proxy,
                               const char *key,
                               GValue *value,
                               gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (g_strcmp0 (key, "Attached") == 0 && G_VALUE_HOLDS_BOOLEAN (value))
		handle_attached (self, value);
}

static void
handle_subscriber_identity (NMModemOfono *self, GValue *value)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	const gchar *value_str = g_value_get_string (value);

	/* Check for empty DBus string value */
	if (g_strcmp0 (value_str, "(null)") != 0) {

		if (g_strcmp0 (value_str, priv->imsi) != 0) {

			if (priv->imsi != NULL) {
				nm_log_warn (LOGD_MB, "SimManager:'SubscriberIdentity' changed: %s", priv->imsi);
				g_free(priv->imsi);
			}

			nm_log_info (LOGD_MB, "GetPropsDone: 'SubscriberIdentity': %s", priv->imsi);

			priv->imsi = g_strdup (value_str);
			update_modem_state (self);
		}
	}
}


static void
get_ofono_sim_properties_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	GError *error = NULL;
	GHashTable *properties = NULL;
	GValue *value = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
		                        DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
		                        G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed to get ofono SimManager properties: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		goto done;
	}

	value = g_hash_table_lookup (properties, "SubscriberIdentity");

	if (value) {
		handle_subscriber_identity (self, value);
		g_value_unset (value);
	} else {
		nm_log_warn (LOGD_MB, "failed to get SimManager:'SubscriberIdentity'; not found");
	}

done:
	g_object_unref (self);

}

static void
ofono_sim_properties_changed (DBusGProxy *proxy,
                              const char *key,
                              GValue *value,
                              gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);

	if (g_strcmp0 (key, "SubscriberIdentity") == 0 && G_VALUE_HOLDS_STRING (value))
		handle_subscriber_identity (self, value);
}

static void
ofono_context_added (DBusGProxy *proxy,
                     const char *path,
                     GValue *prop,
                     gpointer user_data)
{
	nm_log_dbg (LOGD_MB, "context %s added", path);
}

static void
ofono_context_removed (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	nm_log_dbg (LOGD_MB, "context %s removed", path);
}

static void
ofono_properties_changed (DBusGProxy *proxy,
                          const char *key,
                          GValue *value,
                          gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	gboolean online;

	nm_log_dbg (LOGD_MB, "in %s: %s", __func__, key);

	if (g_strcmp0 (key, "Online") == 0 && G_VALUE_HOLDS_BOOLEAN (value)) {

		online = g_value_get_boolean (value);
		if (online != priv->modem_online) {
			priv->modem_online = online;

			nm_log_info (LOGD_MB, "(%s) modem is now %s",
			             nm_modem_get_path (NM_MODEM (self)),
			             online ? "Online" : "Offline");

			update_modem_state (self);
		}

	} else if (g_strcmp0 (key, "Interfaces") == 0 && G_VALUE_HOLDS_BOXED (value)) {
		gboolean found_simmanager = FALSE;
		gboolean found_conn_manager = FALSE;
		int i;

		priv->interfaces = (char **) g_value_get_boxed (value);
		nm_log_info (LOGD_MB, "(%s) updated available interfaces", nm_modem_get_path (NM_MODEM (self)));

		for (i = 0; priv->interfaces[i]; i++) {
			if (g_strrstr (priv->interfaces[i], "SimManager"))
				found_simmanager = TRUE;
			if (g_strrstr (priv->interfaces[i], "ConnectionManager"))
				found_conn_manager = TRUE;
		}

		if (found_simmanager) {
			if (!priv->simmanager_proxy) {
				nm_log_info (LOGD_MB, "(%s): found new SimManager interface",
				             nm_modem_get_path (NM_MODEM (self)));
				priv->simmanager_proxy = get_ofono_proxy (self,
				                                          nm_modem_get_path (NM_MODEM (self)),
				                                          OFONO_DBUS_INTERFACE_SIM_MANAGER);
				dbus_g_proxy_add_signal (priv->simmanager_proxy, "PropertyChanged",
				                         G_TYPE_STRING, G_TYPE_VALUE,
				                         G_TYPE_INVALID);
				dbus_g_proxy_connect_signal (priv->simmanager_proxy, "PropertyChanged",
				                             G_CALLBACK (ofono_sim_properties_changed),
				                             self,
				                             NULL);

				dbus_g_proxy_begin_call_with_timeout (priv->simmanager_proxy,
				                                      "GetProperties",
				                                      get_ofono_sim_properties_done,
				                                      g_object_ref (self), NULL, 20000,
				                                      G_TYPE_INVALID);
			}
		} else if (priv->simmanager_proxy) {
				nm_log_info (LOGD_MB, "(%s): SimManager interface disappeared",
				             nm_modem_get_path (NM_MODEM (self)));
				g_object_unref (priv->simmanager_proxy);
				priv->simmanager_proxy = NULL;

				g_free (priv->imsi);
				priv->imsi = NULL;

				update_modem_state (self);
		}

		if (found_conn_manager) {
			if (!priv->connman_proxy) {
				nm_log_info (LOGD_MB, "(%s): found new ConnectionManager interface",
				             nm_modem_get_path (NM_MODEM (self)));

				priv->connman_proxy = get_ofono_proxy (self,
				                                       nm_modem_get_path (NM_MODEM (self)),
				                                       OFONO_DBUS_INTERFACE_CONNECTION_MANAGER);

				if (priv->connman_proxy) {

					dbus_g_proxy_begin_call_with_timeout (priv->connman_proxy,
					                                      "GetProperties",
					                                      get_ofono_conn_manager_properties_done,
					                                      g_object_ref (self), NULL, 20000,
					                                      G_TYPE_INVALID);

					dbus_g_proxy_add_signal (priv->connman_proxy, "PropertyChanged",
					                         G_TYPE_STRING, G_TYPE_VALUE,
					                         G_TYPE_INVALID);
					dbus_g_proxy_connect_signal (priv->connman_proxy, "PropertyChanged",
					                             G_CALLBACK (ofono_conn_properties_changed),
					                             self,
					                             NULL);

					dbus_g_proxy_add_signal (priv->connman_proxy, "ContextAdded",
					                         DBUS_TYPE_G_OBJECT_PATH, DBUS_TYPE_G_MAP_OF_VARIANT,
					                         G_TYPE_INVALID);
					dbus_g_proxy_connect_signal (priv->connman_proxy, "ContextAdded",
					                             G_CALLBACK (ofono_context_added),
					                             self,
					                             NULL);
					dbus_g_proxy_add_signal (priv->connman_proxy, "ContextRemoved",
					                         DBUS_TYPE_G_OBJECT_PATH,
					                         G_TYPE_INVALID);
					dbus_g_proxy_connect_signal (priv->connman_proxy, "ContextRemoved",
					                             G_CALLBACK (ofono_context_removed),
					                             self,
					                             NULL);
				}
			}
		} else if (priv->connman_proxy) {
			nm_log_info (LOGD_MB, "(%s): ConnectionManager interface disappeared",
			             nm_modem_get_path (NM_MODEM (self)));
			g_object_unref (priv->connman_proxy);
			priv->connman_proxy = NULL;

			/* The connection manager proxy disappeared, we should
			 * consider the modem disabled.
			 */
			priv->gprs_attached = FALSE;

			update_modem_state (self);
		}
	}
}

NMModem *
nm_modem_ofono_new (const char *path)
{
	nm_log_dbg (LOGD_MB, "in %s", __func__);
	g_return_val_if_fail (path != NULL, NULL);

	nm_log_dbg (LOGD_MB, "in %s: path %s", __func__, path);

	return (NMModem *) g_object_new (NM_TYPE_MODEM_OFONO,
	                                 NM_MODEM_PATH, path,
	                                 NM_MODEM_UID, (path + 1),
	                                 NM_MODEM_DEVICE_ID, (path + 1),
	                                 NM_MODEM_CONTROL_PORT, "ofono", /* mandatory */
	                                 NM_MODEM_DRIVER, "ofono",
	                                 NM_MODEM_STATE, NM_MODEM_STATE_INITIALIZING,
	                                 NULL);
}

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GError *error = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (!dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "OFONO connection failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_BUSY);

		/*
		 * FIXME: add code to check for InProgress so that the
		 * connection doesn't continue to try and activate,
		 * leading to the connection being disabled, and a 5m
		 * timeout...
		 */

		g_error_free (error);
	}
}

static void
ofono_context_get_ip_properties (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMPlatformIP4Address addr;
	NMDeviceStateReason reason = NM_DEVICE_STATE_REASON_NONE;
	GHashTable *properties, *ip_settings;
	GError *error = NULL;
	GType prop_dict;
	const gchar *address_string, *gateway_string, *netmask_string, *iface;
	gchar **dns;
	const gchar *mms_proxy;
	gpointer settings;
	gboolean ret = FALSE;
	guint32 address_network, gateway_network;
	guint i;
	guint prefix = 0;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	prop_dict = dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE);
	dbus_g_proxy_call_with_timeout (priv->context_proxy,
	                                "GetProperties",
	                                20000, &error,
	                                G_TYPE_INVALID,
	                                prop_dict, &properties,
	                                G_TYPE_INVALID);

	if (!error) {
		settings = g_hash_table_lookup (properties, "Settings");
		if (settings && G_VALUE_HOLDS_BOXED (settings)) {
			ip_settings = (GHashTable*) g_value_get_boxed (settings);

			if (nm_modem_get_state (NM_MODEM (self)) == NM_MODEM_STATE_CONNECTED
			    && g_hash_table_size(ip_settings) <= 0) {
				g_signal_emit_by_name (self, NM_MODEM_PPP_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
				return;
			}

			nm_log_info (LOGD_MB, "(%s): IPv4 static configuration:",
			             nm_modem_get_uid (NM_MODEM (self)));

			iface = g_value_get_string (g_hash_table_lookup (ip_settings, "Interface"));
			if (iface)
				g_object_set (self, NM_MODEM_DATA_PORT, iface,
				                    NM_MODEM_IP4_METHOD, NM_MODEM_IP_METHOD_STATIC,
				              NULL);

			if (priv->ip4_config)
				g_object_unref (priv->ip4_config);
			priv->ip4_config = nm_ip4_config_new ();
			memset (&addr, 0, sizeof (addr));

			address_string = g_value_get_string (g_hash_table_lookup (ip_settings, "Address"));
			if (address_string) {
				if (ip_string_to_network_address (address_string, &address_network)) {
					addr.address = address_network;
					addr.source = NM_IP_CONFIG_SOURCE_WWAN;
				}
			} else
				goto out;

			/* retrieve netmask and convert to prefix value */
			netmask_string = g_value_get_string (g_hash_table_lookup (ip_settings, "Netmask"));
			if (ip_string_to_network_address (netmask_string, &address_network)) {
				prefix = nm_utils_ip4_netmask_to_prefix (address_network);
				if (prefix > 0)
					addr.plen = prefix;
			} else
				goto out;

			nm_log_info (LOGD_MB, "  address %s/%d", address_string, prefix);
			nm_ip4_config_add_address (priv->ip4_config, &addr);

			gateway_string = g_value_get_string (g_hash_table_lookup (ip_settings, "Gateway"));
			if (gateway_string) {
				if (ip_string_to_network_address (gateway_string, &gateway_network)) {
					nm_log_info (LOGD_MB, "  gateway %s", gateway_string);
					nm_ip4_config_set_gateway (priv->ip4_config, gateway_network);
				}
			} else
				goto out;

			/* DNS servers */
			dns = (char **) g_value_get_boxed (g_hash_table_lookup (ip_settings, "DomainNameServers"));
			for (i = 0; dns[i]; i++) {
				if (   ip_string_to_network_address (dns[i], &address_network)
				    && address_network > 0) {
				    nm_ip4_config_add_nameserver (priv->ip4_config, address_network);
				    nm_log_info (LOGD_MB, "  DNS %s", dns[i]);
				}
			}

			/* Handle the case for a shared internet and MMS context */
			mms_proxy = g_value_get_string (g_hash_table_lookup (properties, "MessageProxy"));
			if (mms_proxy) {
				nm_log_info (LOGD_MB, "  mms proxy: %s", mms_proxy);

				/* If the value can't be mapped to a guint32, it's probably not
				 * an IP address; so we could access it via *any* internet
				 * connection anyway, no need for a specific host route.
				 */
				if (ip_string_to_network_address (mms_proxy, &address_network)) {
					NMPlatformIP4Route mms_route;

					memset (&mms_route, 0, sizeof (mms_route));
					mms_route.network = address_network;
					mms_route.plen = 32;
					mms_route.gateway = gateway_network;

					/* Setting a very low metric as MMS should go through
					 * the 3G connection...
					 */
					mms_route.metric = 1;

					nm_ip4_config_add_route (priv->ip4_config, &mms_route);
				}
			}

			ret = TRUE;
		}
	}

out:
	if (!ret) {
		if (error) {
			reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
			g_clear_error (&error);
		} else {
			reason = NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE;
		}
	}

	if (nm_modem_get_state (NM_MODEM (self)) != NM_MODEM_STATE_CONNECTED)
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, ret, reason);
}

static void
context_properties_changed (DBusGProxy *proxy,
                            const char *key,
                            GValue *value,
                            gpointer user_data)
{
	NMModemOfono *self = NM_MODEM_OFONO (user_data);

	if (g_strcmp0("Settings", key) == 0) {
		ofono_context_get_ip_properties (self);
	}
}

static void
do_context_activate (NMModemOfono *self, char *context_path)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	GValue value = G_VALUE_INIT;

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_MODEM_OFONO (self));

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, TRUE);

	if (priv->context_proxy)
		g_object_unref (priv->context_proxy);

	priv->context_proxy = get_ofono_proxy (self,
	                                       context_path,
	                                       OFONO_DBUS_INTERFACE_CONNECTION_CONTEXT);

	if (!priv->context_proxy) {
		nm_log_err (LOGD_MB, "could not bring up connection context proxy");
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_BUSY);
		return;
	}

	if (!priv->gprs_attached) {
		g_signal_emit_by_name (self, NM_MODEM_PREPARE_RESULT, FALSE,
		                       NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
		return;
	}

	if (priv->ip4_config) {
		/* We have an old copy of the settings from a previous activation,
		 * clear it so that we can gate getting the IP config from oFono
		 * on whether or not we have already received them
		 */
		g_object_unref (priv->ip4_config);
		priv->ip4_config = NULL;
	}

	dbus_g_proxy_add_signal (priv->context_proxy, "PropertyChanged",
	                         G_TYPE_STRING, G_TYPE_VALUE,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->context_proxy, "PropertyChanged",
	                             G_CALLBACK (context_properties_changed),
	                             self,
	                             NULL);

	dbus_g_proxy_begin_call_with_timeout (priv->context_proxy,
	                                      "SetProperty", stage1_prepare_done,
	                                      g_object_ref (self), NULL, 40000,
	                                      G_TYPE_STRING, "Active",
	                                      G_TYPE_VALUE, &value,
	                                      G_TYPE_INVALID);

}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingGsm *setting;
	GHashTable *properties;
	const char *str;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	setting = nm_connection_get_setting_gsm (connection);
	properties = g_hash_table_new (g_str_hash, g_str_equal);

	str = nm_setting_gsm_get_apn (setting);
	if (str)
		g_hash_table_insert (properties, "AccessPointName", g_strdup (str));

	str = nm_setting_gsm_get_username (setting);
	if (str)
		g_hash_table_insert (properties, "Username", g_strdup (str));

	str = nm_setting_gsm_get_password (setting);
	if (str)
		g_hash_table_insert (properties, "Password", g_strdup (str));

	return properties;
}

static NMActStageReturn
act_stage1_prepare (NMModem *modem,
                    NMConnection *connection,
                    NMDeviceStateReason *reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	const char *context_id;
	char **id = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	context_id = nm_connection_get_id (connection);
	id = g_strsplit (context_id, "/", 0);
	g_assert (id[2]);

	nm_log_dbg (LOGD_MB, " trying %s %s", id[1], id[2]);

	if (priv->context_path)
		g_free (priv->context_path);

	priv->context_path = g_strdup_printf ("%s/%s",
	                                      nm_modem_get_path (modem),
	                                      id[2]);
	g_strfreev (id);

	if (!priv->context_path) {
		*reason = NM_DEVICE_STATE_REASON_GSM_APN_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (priv->connect_properties)
		g_hash_table_destroy (priv->connect_properties);
	priv->connect_properties = create_connect_properties (connection);

	nm_log_info (LOGD_MB, "(%s): activating context %s",
	             nm_modem_get_path (modem),
	             priv->context_path);

	if (nm_modem_get_state (modem) == NM_MODEM_STATE_REGISTERED) {
		do_context_activate (self, priv->context_path);
	} else {
		nm_log_warn (LOGD_MB, "(%s): could not activate context, "
		             "modem is not registered.",
		             nm_modem_get_path (modem));
		*reason = NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
static_stage3_ip4_config_start (NMModem *_self,
                                NMActRequest *req,
                                NMDeviceStateReason *reason)
{
	NMModemOfono *self = NM_MODEM_OFONO (_self);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;
	GError *error = NULL;

	if (priv->ip4_config) {
		g_signal_emit_by_name (self, NM_MODEM_IP4_CONFIG_RESULT, priv->ip4_config, error);
		priv->ip4_config = NULL;
		nm_modem_set_state (NM_MODEM (self),
		                    NM_MODEM_STATE_CONNECTED,
		                    nm_modem_state_to_string (NM_MODEM_STATE_CONNECTED));
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}

	return ret;
}

static gboolean
check_connection_compatible (NMModem *modem,
                             NMConnection *connection)
{
	NMModemOfono *self = NM_MODEM_OFONO (modem);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;
	const char *uuid;
	const char *id;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	uuid = nm_connection_get_uuid (connection);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_GSM_SETTING_NAME)) {
		nm_log_dbg (LOGD_MB, "%s isn't of the right type, skipping.", uuid);
		return FALSE;
	}

	s_gsm = nm_connection_get_setting_gsm (connection);
	if (!s_gsm)
		return FALSE;

	id = nm_connection_get_id (connection);
	if (!g_strrstr (id, "/context")) {
		nm_log_dbg (LOGD_MB, "%s (%s) isn't of the right type, skipping.", id, uuid);
		return FALSE;
	}

	if (! g_strrstr (id, priv->imsi)) {
		nm_log_dbg (LOGD_MB, "%s (%s) isn't for the right SIM, skipping.", id, uuid);
		return FALSE;
	}

	nm_log_dbg (LOGD_MB, "%s (%s) looks compatible with IMSI %s", id, uuid, priv->imsi);

	return TRUE;
}

static void
get_ofono_properties_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	GError *error = NULL;
	GHashTable *properties = NULL;
	GValue *value = NULL;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
		                        DBUS_TYPE_G_MAP_OF_VARIANT, &properties,
		                        G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "failed get modem enabled state: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		return;
	}

	value = g_hash_table_lookup (properties, "Online");
	if (value)
		ofono_properties_changed (NULL, "Online", value, self);
	else
		nm_log_warn (LOGD_MB, "failed get modem online state: unexpected reply type");
	g_value_unset (value);

	value = g_hash_table_lookup (properties, "Interfaces");
	if (value)
		ofono_properties_changed (NULL, "Interfaces", value, self);
	else
		nm_log_warn (LOGD_MB, "failed get available oFono interfaces: unexpected reply type");
	g_value_unset (value);
}

static void
query_ofono_properties (NMModemOfono *self)
{
	nm_log_dbg (LOGD_MB, "in %s", __func__);
	dbus_g_proxy_begin_call (NM_MODEM_OFONO_GET_PRIVATE (self)->modem_proxy,
	                         "GetProperties", get_ofono_properties_done,
	                         self, NULL,
	                         G_TYPE_INVALID);
}

static void
get_capabilities (NMModem *_self,
                  NMDeviceModemCapabilities *modem_caps,
                  NMDeviceModemCapabilities *current_caps)
{
	NMDeviceModemCapabilities all_ofono_caps = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;

	*modem_caps = all_ofono_caps;
	*current_caps = all_ofono_caps;
}

static void
nm_modem_ofono_init (NMModemOfono *self)
{
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	priv->dbus_mgr = nm_dbus_manager_get ();

	priv->modem_proxy = NULL;
	priv->connman_proxy = NULL;
	priv->context_proxy = NULL;
	priv->simmanager_proxy = NULL;

	priv->modem_online = FALSE;
	priv->gprs_attached = FALSE;

	priv->ip4_config = NULL;
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;
	NMModemOfonoPrivate *priv;
	DBusGConnection *bus;

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	object = G_OBJECT_CLASS (nm_modem_ofono_parent_class)->constructor (type, n_construct_params, construct_params);
	if (!object)
		return NULL;

	priv = NM_MODEM_OFONO_GET_PRIVATE (object);
	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->modem_proxy = get_ofono_proxy (NM_MODEM_OFONO (object),
	                                     nm_modem_get_path (NM_MODEM (object)),
	                                     OFONO_DBUS_INTERFACE_MODEM);

	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_VALUE,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->modem_proxy, "PropertyChanged",
	                         G_TYPE_STRING, G_TYPE_VALUE,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->modem_proxy, "PropertyChanged",
	                             G_CALLBACK (ofono_properties_changed),
	                             object,
	                             NULL);

	query_ofono_properties (NM_MODEM_OFONO (object));

	return object;
}

static void
dispose (GObject *object)
{
	NMModemOfono *self = NM_MODEM_OFONO (object);
	NMModemOfonoPrivate *priv = NM_MODEM_OFONO_GET_PRIVATE (self);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	if (priv->connect_properties) {
		g_hash_table_destroy (priv->connect_properties);
		priv->connect_properties = NULL;
	}

	if (priv->ip4_config)
		g_clear_object (&priv->ip4_config);

	if (priv->modem_proxy)
		g_clear_object (&priv->modem_proxy);
	if (priv->connman_proxy)
		g_clear_object (&priv->connman_proxy);
	if (priv->context_proxy)
		g_clear_object (&priv->context_proxy);

	if (priv->imsi) {
		g_free (priv->imsi);
		priv->imsi = NULL;
	}

	G_OBJECT_CLASS (nm_modem_ofono_parent_class)->dispose (object);
}

static void
nm_modem_ofono_class_init (NMModemOfonoClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	nm_log_dbg (LOGD_MB, "in %s", __func__);

	g_type_class_add_private (object_class, sizeof (NMModemOfonoPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;

	modem_class->get_capabilities = get_capabilities;
	modem_class->disconnect = disconnect;
	modem_class->disconnect_finish = disconnect_finish;
	modem_class->deactivate_cleanup = deactivate_cleanup;
	modem_class->check_connection_compatible = check_connection_compatible;
	modem_class->act_stage1_prepare = act_stage1_prepare;
	modem_class->static_stage3_ip4_config_start = static_stage3_ip4_config_start;
}

