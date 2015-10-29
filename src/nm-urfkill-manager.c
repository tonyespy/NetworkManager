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
 * Copyright (C) 2006 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "config.h"
#include "nm-core-internal.h"
#include "nm-urfkill-manager.h"
#include "nm-glib-compat.h"

#include <gio/gio.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <string.h>
#include "nm-logging.h"

enum {
	WLAN_STATE_CHANGED,
	WWAN_STATE_CHANGED,
	NUMBER_OF_SIGNALS
};

static guint signals[NUMBER_OF_SIGNALS];

struct _NMUrfkillManager {
	GObject parent_instance;

	guint urfkill_watch;

	GDBusProxy *wlan_proxy;
	GDBusProxy *wwan_proxy;

	GCancellable *watch_cancellable;
	GCancellable *wlan_proxy_cancellable;
	GCancellable *wwan_proxy_cancellable;
};

typedef GObjectClass NMUrfkillManagerClass;

G_DEFINE_TYPE(NMUrfkillManager, nm_urfkill_manager, G_TYPE_OBJECT)

static void
wlan_state_changed (GDBusProxy *proxy,
                    GVariant            *changed_properties,
                    const gchar* const  *invalidated_properties,
                    gpointer             user_data)
{
	NMUrfkillManager *self = NM_URFKILL_MANAGER (user_data);
	gboolean enabled;

	enabled = nm_urfkill_get_wlan_state (self);

	nm_log_dbg (LOGD_RFKILL, "received state change for WLAN: %s",
	            enabled ? "unblocked" : "blocked");

	g_signal_emit (self, signals[WLAN_STATE_CHANGED], 0, enabled);
}

static void
wwan_state_changed (GDBusProxy *proxy,
                    GVariant            *changed_properties,
                    const gchar* const  *invalidated_properties,
                    gpointer             user_data)
{
	NMUrfkillManager *self = NM_URFKILL_MANAGER (user_data);
	gboolean enabled;

	enabled = nm_urfkill_get_wwan_state (self);

	nm_log_dbg (LOGD_RFKILL, "received state change for WWAN: %s",
	            enabled ? "unblocked" : "blocked");

	g_signal_emit (self, signals[WWAN_STATE_CHANGED], 0, enabled);
}

static void
wlan_proxy_created (GObject *source_object,
                    GAsyncResult *res,
                    gpointer user_data)
{
	NMUrfkillManager *self = NM_URFKILL_MANAGER (user_data);
	GDBusProxy *wlan_proxy;
	GError *error;

	wlan_proxy = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (wlan_proxy) {
		self->wlan_proxy = wlan_proxy;

		g_signal_connect (self->wlan_proxy, "g-properties-changed",
		                  G_CALLBACK (wlan_state_changed), self);
		g_signal_emit (self, signals[WLAN_STATE_CHANGED], 0,
		               nm_urfkill_get_wlan_state (self));
	} else {
		nm_log_warn (LOGD_RFKILL, "could not create URfkill WLAN device proxy");
	}
}

static void
wwan_proxy_created (GObject *source_object,
                    GAsyncResult *res,
                    gpointer user_data)
{
	NMUrfkillManager *self = NM_URFKILL_MANAGER (user_data);
	GDBusProxy *wwan_proxy;
	GError *error;

	wwan_proxy = g_dbus_proxy_new_for_bus_finish (res, &error);

	if (wwan_proxy) {
		self->wwan_proxy = wwan_proxy;

		g_signal_connect (self->wwan_proxy, "g-properties-changed",
		                  G_CALLBACK (wwan_state_changed), self);
		g_signal_emit (self, signals[WWAN_STATE_CHANGED], 0,
		               nm_urfkill_get_wwan_state (self));
	} else {
		nm_log_warn (LOGD_RFKILL, "could not create URfkill WWAN device proxy");
	}
}

gboolean
nm_urfkill_get_wlan_state (NMUrfkillManager *self)
{
	GVariant *state;
	gboolean enabled = TRUE;

	g_return_val_if_fail (self->wlan_proxy != NULL, enabled);

	state = g_dbus_proxy_get_cached_property (self->wlan_proxy, "state");

	if (state) {
		nm_log_dbg (LOGD_RFKILL, "wlan state from urfkill: %d",
		            g_variant_get_int32 (state));
		enabled = (g_variant_get_int32 (state) <= 0);
		g_variant_unref (state);
	} else {
		nm_log_warn (LOGD_RFKILL, "invalid wlan state from urfkill cached properties");
	}

	return enabled;
}

gboolean
nm_urfkill_get_wwan_state (NMUrfkillManager *self)
{
	GVariant *state;
	gboolean enabled = TRUE;

	g_return_val_if_fail (self->wwan_proxy != NULL, enabled);

	state = g_dbus_proxy_get_cached_property (self->wwan_proxy, "state");

	if (state) {
		nm_log_dbg (LOGD_RFKILL, "wwan state from urfkill: %d",
		            g_variant_get_int32 (state));
		enabled = (g_variant_get_int32 (state) <= 0);
		g_variant_unref (state);
	} else {
		nm_log_warn (LOGD_RFKILL, "invalid wwan state from urfkill cached properties");
	}

	return enabled;
}

static void
on_urfkill_appeared (GDBusConnection *connection,
                     const gchar     *name,
                     const gchar     *name_owner,
                     gpointer         user_data)
{
	NMUrfkillManager *self = NM_URFKILL_MANAGER (user_data);

	nm_log_info (LOGD_RFKILL, "urfkill appeared on the bus");

	self->wlan_proxy_cancellable = g_cancellable_new ();
	self->wwan_proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_new (connection,
	                  G_DBUS_PROXY_FLAGS_NONE,
	                  NULL,
	                  "org.freedesktop.URfkill",
	                  "/org/freedesktop/URfkill/WLAN",
	                  "org.freedesktop.URfkill.Killswitch",
	                  self->wlan_proxy_cancellable,
	                  wlan_proxy_created,
	                  self);

	g_dbus_proxy_new (connection,
	                  G_DBUS_PROXY_FLAGS_NONE,
	                  NULL,
	                  "org.freedesktop.URfkill",
	                  "/org/freedesktop/URfkill/WWAN",
	                  "org.freedesktop.URfkill.Killswitch",
	                  self->wwan_proxy_cancellable,
	                  wwan_proxy_created,
	                  self);
}

static void
on_urfkill_vanished (GDBusConnection *connection,
                     const gchar     *name,
                     gpointer         user_data)
{
	NMUrfkillManager *self = NM_URFKILL_MANAGER (user_data);

	nm_log_info (LOGD_RFKILL, "urfkill disappeared from the bus");

	if (self->wlan_proxy)
		g_object_unref (self->wlan_proxy);
	if (self->wwan_proxy)
		g_object_unref (self->wwan_proxy);
}

static void
nm_urfkill_manager_init (NMUrfkillManager *self)
{
	self->urfkill_watch = g_bus_watch_name (G_BUS_TYPE_SYSTEM,
	                                        "org.freedesktop.URfkill",
	                                        0,
	                                        on_urfkill_appeared,
	                                        on_urfkill_vanished,
	                                        self,
	                                        NULL);
}

NMUrfkillManager *
nm_urfkill_manager_new (void)
{
        return NM_URFKILL_MANAGER (g_object_new (NM_TYPE_URFKILL_MANAGER, NULL));
}

static void
nm_urfkill_manager_finalize (GObject *object)
{
	NMUrfkillManager *mgr = NM_URFKILL_MANAGER (object);

	if (mgr->wlan_proxy_cancellable)
		g_cancellable_cancel (mgr->wlan_proxy_cancellable);
	if (mgr->wwan_proxy_cancellable)
		g_cancellable_cancel (mgr->wwan_proxy_cancellable);

	if (mgr->urfkill_watch) {
		g_bus_unwatch_name (mgr->urfkill_watch);
		mgr->urfkill_watch = 0;
	}

	if (mgr->wlan_proxy)
		g_object_unref (mgr->wlan_proxy);
	if (mgr->wwan_proxy)
		g_object_unref (mgr->wwan_proxy);

	G_OBJECT_CLASS (nm_urfkill_manager_parent_class)->finalize (object);
}

static void
nm_urfkill_manager_class_init (NMUrfkillManagerClass *class)
{
	class->finalize = nm_urfkill_manager_finalize;

	signals[WLAN_STATE_CHANGED] =
		g_signal_new (NM_URFKILL_MANAGER_WLAN_STATE_CHANGED,
		              G_OBJECT_CLASS_TYPE (class),
		              G_SIGNAL_RUN_LAST, 0,
		              NULL, NULL, g_cclosure_marshal_VOID__BOOLEAN,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[WWAN_STATE_CHANGED] =
		g_signal_new (NM_URFKILL_MANAGER_WWAN_STATE_CHANGED,
		              G_OBJECT_CLASS_TYPE (class),
		              G_SIGNAL_RUN_LAST, 0,
		              NULL, NULL, g_cclosure_marshal_VOID__BOOLEAN,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);
}

