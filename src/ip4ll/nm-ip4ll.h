/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NM_IP4LL_H
#define NM_IP4LL_H

#include <glib-object.h>

#define NM_TYPE_IP4LL            (nm_ip4ll_get_type ())
#define NM_IP4LL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP4LL, NMIP4ll))
#define NM_IP4LL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP4LL, NMIP4llClass))
#define NM_IS_IP4LL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP4LL))
#define NM_IS_IP4LL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_IP4LL))
#define NM_IP4LL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP4LL, NMIP4llClass))

/* Signals */
#define NM_IP4LL_TIMEOUT  "timeout"
#define NM_IP4LL_BOUND    "bound"
#define NM_IP4LL_CONFLICT "conflict"

typedef struct _NMIP4llPrivate NMIP4llPrivate;

typedef struct {
	GObject parent;
	NMIP4llPrivate *priv;
} NMIP4ll;

typedef struct {
	GObjectClass parent;

	void (*timeout)  (NMIP4ll *self);
	void (*bound)    (NMIP4ll *self, guint32 address);
	void (*conflict) (NMIP4ll *self);
} NMIP4llClass;

GType nm_ip4ll_get_type (void);

NMIP4ll *nm_ip4ll_new (int ifindex);

#endif /* NM_IP4_CONFIG_H */
