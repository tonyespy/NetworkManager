/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager system settings service (ofono)
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
#include <glib/gstdio.h>
#include "nm-core-internal.h"
#include <nm-utils.h>
#include <nm-setting-wireless-security.h>
#include <nm-settings-connection.h>
#include <nm-system-config-interface.h>
#include "nm-ofono-connection.h"
#include "parser.h"

G_DEFINE_TYPE (NMOfonoConnection, nm_ofono_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_OFONO_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OFONO_CONNECTION, NMOfonoConnectionPrivate))

typedef struct {
	GHashTable *context;
} NMOfonoConnectionPrivate;

enum {
	PROP_ZERO,
	PROP_CONTEXT,
	_PROP_END,
};


NMOfonoConnection*
nm_ofono_connection_new (GHashTable *context)
{
	g_return_val_if_fail (context != NULL, NULL);

	return (NMOfonoConnection *) g_object_new (NM_TYPE_OFONO_CONNECTION,
	                                           NM_OFONO_CONNECTION_CONTEXT, context,
	                                           NULL);
}

static gboolean
supports_secrets (NMSettingsConnection *connection, const char *setting_name)
{
	return FALSE;
}

static void
nm_ofono_connection_init (NMOfonoConnection *connection)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMOfonoConnectionPrivate *priv;
	GError *error = NULL;

	object = G_OBJECT_CLASS (nm_ofono_connection_parent_class)->constructor (type, n_construct_params, construct_params);
	g_return_val_if_fail (object, NULL);

	priv = NM_OFONO_CONNECTION_GET_PRIVATE (object);
	if (!priv) {
		g_warning ("%s.%d - no private instance.", __FILE__, __LINE__);
		goto err;
	}
	if (!priv->context) {
		g_warning ("(ofono) context not provided to constructor.");
		goto err;
	}

	if (!ofono_update_connection_from_context (NM_CONNECTION (object), priv->context, &error)) {
		g_warning ("%s.%d - invalid connection read from Ofono: (%d) %s",
		           __FILE__,
		           __LINE__,
		           error ? error->code : -1,
		           error && error->message ? error->message : "(unknown)");
		goto err;
	}

	return object;

 err:
	g_object_unref (object);
	return NULL;
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMOfonoConnectionPrivate *priv = NM_OFONO_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_CONTEXT:
		priv->context = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMOfonoConnectionPrivate *priv = NM_OFONO_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_CONTEXT:
		g_value_set_pointer (value, priv->context);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ofono_connection_class_init (NMOfonoConnectionClass *ofono_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ofono_connection_class);
	NMSettingsConnectionClass *connection_class = NM_SETTINGS_CONNECTION_CLASS (ofono_connection_class);

	g_type_class_add_private (ofono_connection_class, sizeof (NMOfonoConnectionPrivate));

	/* Virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	connection_class->supports_secrets = supports_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_CONTEXT,
		 g_param_spec_pointer (NM_OFONO_CONNECTION_CONTEXT,
						   "context",
						   "",
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

