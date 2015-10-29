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
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NM_URFKILL_MANAGER_H__
#define __NM_URFKILL_MANAGER_H__

#include <glib-object.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define NM_TYPE_URFKILL_MANAGER (nm_urfkill_manager_get_type ())
#define NM_URFKILL_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_URFKILL_MANAGER, NMUrfkillManager))
#define NM_IS_URFKILL_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_URFKILL_MANAGER))

#define NM_URFKILL_MANAGER_WLAN_STATE_CHANGED "wlan-state-changed"
#define NM_URFKILL_MANAGER_WWAN_STATE_CHANGED "wwan-state-changed"

typedef struct _NMUrfkillManager NMUrfkillManager;

GType nm_urfkill_manager_get_type (void);

NMUrfkillManager *nm_urfkill_manager_new ();

gboolean nm_urfkill_get_wlan_state (NMUrfkillManager *self);
gboolean nm_urfkill_get_wwan_state (NMUrfkillManager *self);

G_END_DECLS

#endif /* __NM_URFKILL_MANAGER_H__ */
