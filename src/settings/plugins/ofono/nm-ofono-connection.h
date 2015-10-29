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

#ifndef NM_OFONO_CONNECTION_H
#define NM_OFONO_CONNECTION_H

#include <nm-settings-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_OFONO_CONNECTION            (nm_ofono_connection_get_type ())
#define NM_OFONO_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OFONO_CONNECTION, NMOfonoConnection))
#define NM_OFONO_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OFONO_CONNECTION, NMOfonoConnectionClass))
#define NM_IS_OFONO_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OFONO_CONNECTION))
#define NM_IS_OFONO_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OFONO_CONNECTION))
#define NM_OFONO_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OFONO_CONNECTION, NMOfonoConnectionClass))

#define NM_OFONO_CONNECTION_CONTEXT "context"

typedef struct {
	NMSettingsConnection parent;
} NMOfonoConnection;

typedef struct {
	NMSettingsConnectionClass parent;
} NMOfonoConnectionClass;

GType nm_ofono_connection_get_type (void);

NMOfonoConnection *nm_ofono_connection_new (GHashTable *context);

G_END_DECLS

#endif /* NM_OFONO_CONNECTION_H */
