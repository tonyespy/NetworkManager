/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-netns-controller.h"

#include <gmodule.h>

#include "nm-dbus-interface.h"
#include "config.h"
#include "nmp-netns.h"
#include "nm-platform.h"
#include "nm-linux-platform.h"
#include "nm-device.h"
#include "nm-netns.h"
#include "NetworkManagerUtils.h"

#include "nmdbus-netns-controller.h"

G_DEFINE_TYPE (NMNetnsController, nm_netns_controller, NM_TYPE_EXPORTED_OBJECT)

NM_GOBJECT_PROPERTIES_DEFINE (NMNetnsController,
	PROP_NETWORK_NAMESPACES,
);

enum {
	NETNS_ADDED,
	NETNS_REMOVED,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMNetns *root_ns;
	GHashTable *network_namespaces;
} NMNetnsControllerPrivate;

#define NM_NETNS_CONTROLLER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS_CONTROLLER, NMNetnsControllerPrivate))

NM_DEFINE_SINGLETON_GETTER (NMNetnsController, nm_netns_controller_get, NM_TYPE_NETNS_CONTROLLER);

#define NETNS_ROOT_NAME           "rootns"

static void namespace_destroy (gpointer data);

/******************************************************************/

static const char *
find_netns_key_by_name(NMNetnsController *self, const char *netnsname)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, priv->network_namespaces);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (!strcmp(netnsname, nm_netns_get_name(value)))
			return key;
	}

	return NULL;
}


/******************************************************************/

NMNetns *
nm_netns_controller_get_root_netns (void)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	return priv->root_ns;
}

NMNetns *
nm_netns_controller_find_netns_by_path(const char *netns_path)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	return g_hash_table_lookup (priv->network_namespaces, netns_path);
}

NMNetns *
nm_netns_controller_find_netns_by_name(const char *netns_name)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);
	GHashTableIter iter;
	gpointer value;

	g_hash_table_iter_init (&iter, priv->network_namespaces);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		if (!strcmp (nm_netns_get_name(value), netns_name))
			return value;
	}

	return NULL;
}

/******************************************************************/

NMDevice *
nm_netns_controller_find_device_by_path (const char *device_path)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);
	GHashTableIter iter;
	gpointer value;
	NMDevice *device;

	g_hash_table_iter_init (&iter, priv->network_namespaces);
	while (g_hash_table_iter_next (&iter, NULL, &value)) {
		if ((device = nm_netns_get_device_by_path (value, device_path)) != NULL)
			return device;
	}

	return NULL;
}

/******************************************************************/

static void
namespace_destroy (gpointer data)
{
	NMNetns *netns = data;

	g_return_if_fail (NM_IS_NETNS (netns));

	nm_netns_stop (netns);
	nm_exported_object_clear_and_unexport (&netns);
}

static NMNetns *
create_new_namespace (NMNetnsController *self, const char *netnsname)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	NMNetns *netns;
	nm_auto_pop_netns NMPNetns *netnsp = NULL;
	const char *path;

	netnsp = nmp_netns_new ();
	if (!netnsp) {
		nm_log_err (LOGD_NETNS, "error creating namespace");
		return NULL;
	}

	netns = nm_netns_new (netnsname);

	if (!nm_netns_setup (netns)) {
		nm_log_dbg (LOGD_NETNS, "error setting up namespace %s ", netnsname);
		g_object_unref (netns);
		return NULL;
	}

	path = nm_exported_object_export (NM_EXPORTED_OBJECT (netns));
	g_hash_table_insert (priv->network_namespaces, g_strdup (path), netns);

	g_signal_emit (self, signals[NETNS_ADDED], 0, netns);
	_notify (self, PROP_NETWORK_NAMESPACES);

	return netns;
}

NMNetns *
nm_netns_controller_new_netns (const char *netns_name)
{
	return create_new_namespace (singleton_instance, netns_name);
}

void
nm_netns_controller_remove_netns (NMNetnsController *self,
                                  NMNetns *netns)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	const char *path;

	path = nm_exported_object_get_path ( NM_EXPORTED_OBJECT(netns));

	nm_log_dbg (LOGD_NETNS, "Removing network namespace %s (path %s)", nm_netns_get_name (netns), path);

	/* Emit removal D-Bus signal */
	g_signal_emit (self, signals[NETNS_REMOVED], 0, netns);

	/* Stop network namespace */
	nm_netns_stop(netns);

	/* Remove network namespace from a list */
	g_hash_table_remove(priv->network_namespaces, path);

	_notify (self, PROP_NETWORK_NAMESPACES);
}

/******************************************************************/

static void
impl_netns_controller_list_namespaces (NMNetnsController *self,
                                       GDBusMethodInvocation *context)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	GPtrArray *network_namespaces;
	GHashTableIter iter;
	gpointer key;

	network_namespaces = g_ptr_array_sized_new (g_hash_table_size (priv->network_namespaces) + 1);
	g_hash_table_iter_init (&iter, priv->network_namespaces);
	while (g_hash_table_iter_next (&iter, &key, NULL))
		g_ptr_array_add (network_namespaces, key);
	g_ptr_array_add (network_namespaces, NULL);

	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(^ao)", network_namespaces->pdata));
	g_ptr_array_unref (network_namespaces);
}

static void
impl_netns_controller_add_namespace (NMNetnsController *self,
                                     GDBusMethodInvocation *context,
                                     const char *netnsname)
{
	NMNetns *netns;

	if ((netns = create_new_namespace (self, netnsname)) != NULL) {
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(o)",
		                                       nm_exported_object_get_path (NM_EXPORTED_OBJECT (netns))));
	} else {
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_FAILED,
		                                       "Error creating network namespace");
	}
}

static void
impl_netns_controller_remove_namespace (NMNetnsController *self,
                                        GDBusMethodInvocation *context,
                                        const char *netnsname)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	NMNetns *netns;
	const char *path;

	path = find_netns_key_by_name(self, netnsname);

	nm_log_dbg (LOGD_NETNS, "Removing network namespace %s (path %s)",
	            netnsname, path);

	if (path == NULL) {
		nm_log_err (LOGD_NETNS, "Network namespace %s not found", netnsname);
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_NOT_FOUND,
		                                       "Network name space not found");
		return;
	}

	netns = g_hash_table_lookup (priv->network_namespaces, path);

	if (netns == priv->root_ns) {
		nm_log_err (LOGD_NETNS, "Root namespace %s can not be removed", netnsname);
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_PERMISSION_DENIED,
		                                       "Root network namespace can not be removed");
		return;
	}

	nm_netns_controller_remove_netns (self, netns);

	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(s)",
	                                       "Success"));
}

/******************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMNetnsController *self = NM_NETNS_CONTROLLER (object);
	NMNetnsControllerPrivate *priv =  NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_NETWORK_NAMESPACES: {
		GHashTableIter iter;
		gpointer key;
		char **paths;
		guint i;

		paths = g_new (char *, g_hash_table_size (priv->network_namespaces) + 1);

		i = 0;
		g_hash_table_iter_init (&iter, priv->network_namespaces);
		while (g_hash_table_iter_next (&iter, &key, NULL))
			paths[i++] = g_strdup (key);
		paths[i] = NULL;
		g_value_take_boxed (value, paths);
		break;
	}
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_netns_controller_init (NMNetnsController *self)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	priv->network_namespaces = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, namespace_destroy);
}

static void
constructed (GObject *object)
{
	NMNetnsController *self = NM_NETNS_CONTROLLER (object);
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	NMNetns *netns;
	const char *path;

	G_OBJECT_CLASS (nm_netns_controller_parent_class)->constructed (object);

	netns = nm_netns_new (NETNS_ROOT_NAME);
	if (!nm_netns_setup (netns))
		nm_log_err (LOGD_NETNS, "error setting up root namespace %s", NETNS_ROOT_NAME);

	path = nm_exported_object_export (NM_EXPORTED_OBJECT (netns));
	g_hash_table_insert (priv->network_namespaces, g_strdup (path), netns);

	priv->root_ns = g_object_ref (netns);
}

static void
dispose (GObject *object)
{
	NMNetnsController *self = NM_NETNS_CONTROLLER (object);
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	if (priv->network_namespaces) {
		g_hash_table_destroy (priv->network_namespaces);
		priv->network_namespaces = NULL;
	}

	g_clear_object (&priv->root_ns);

	G_OBJECT_CLASS (nm_netns_controller_parent_class)->dispose (object);
}

static void
nm_netns_controller_class_init (NMNetnsControllerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMNetnsControllerPrivate));

	exported_object_class->export_path = NM_DBUS_PATH_NETNS_CONTROLLER;
	exported_object_class->export_on_construction = TRUE;

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	obj_properties[PROP_NETWORK_NAMESPACES] =
	    g_param_spec_boxed (NM_NETNS_CONTROLLER_NETWORK_NAMESPACES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);
	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	/* Signals */
	signals[NETNS_ADDED] =
	    g_signal_new (NM_NETNS_CONTROLLER_NETNS_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_NETNS);

	signals[NETNS_REMOVED] =
	    g_signal_new (NM_NETNS_CONTROLLER_NETNS_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_NETNS);

	// TODO: Signal that namespace is removed

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_NETWORK_NAMESPACES_CONTROLLER_SKELETON,
	                                        "ListNetworkNamespaces", impl_netns_controller_list_namespaces,
	                                        "AddNetworkNamespace", impl_netns_controller_add_namespace,
	                                        "RemoveNetworkNamespace", impl_netns_controller_remove_namespace,
	                                        NULL);
}

