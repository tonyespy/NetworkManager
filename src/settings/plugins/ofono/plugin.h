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

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include <glib-object.h>

#define PLUGIN_NAME "ofono"

#define SC_TYPE_PLUGIN_OFONO            (sc_plugin_ofono_get_type ())
#define SC_PLUGIN_OFONO(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_PLUGIN_OFONO, SCPluginOfono))
#define SC_PLUGIN_OFONO_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_PLUGIN_OFONO, SCPluginOfonoClass))
#define SC_IS_PLUGIN_OFONO(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_PLUGIN_OFONO))
#define SC_IS_PLUGIN_OFONO_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_PLUGIN_OFONO))
#define SC_PLUGIN_OFONO_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SC_TYPE_PLUGIN_OFONO, SCPluginOfonoClass))

typedef struct _SCPluginOfono SCPluginOfono;
typedef struct _SCPluginOfonoClass SCPluginOfonoClass;

struct _SCPluginOfono {
	GObject parent;
};

struct _SCPluginOfonoClass {
	GObjectClass parent;
};

GType sc_plugin_ofono_get_type (void);

GQuark ofono_plugin_error_quark (void);

#endif	/* _PLUGIN_H_ */
