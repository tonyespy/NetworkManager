/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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

#ifndef NM_GDHCP_H
#define NM_GDHCP_H

#include <glib.h>
#include <glib-object.h>

#include "nm-dhcp-client.h"

#define NM_TYPE_GDHCP            (nm_gdhcp_get_type ())
#define NM_GDHCP(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_GDHCP, NMGdhcp))
#define NM_GDHCP_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_GDHCP, NMGdhcpClass))
#define NM_IS_GDHCP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_GDHCP))
#define NM_IS_GDHCP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_GDHCP))
#define NM_GDHCP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_GDHCP, NMGdhcpClass))

typedef struct {
	NMDHCPClient parent;
} NMGdhcp;

typedef struct {
	NMDHCPClientClass parent;
} NMGdhcpClass;

GType nm_gdhcp_get_type (void);

GSList *nm_gdhcp_get_lease_ip_configs (const char *iface,
                                       const char *uuid,
                                       gboolean ipv6);

#endif /* NM_GDHCP_H */

