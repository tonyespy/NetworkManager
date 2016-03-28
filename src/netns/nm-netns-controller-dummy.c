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
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

/*
 * This is a dummy implementation of network namespace controller that
 * doesn't use any namespaces but provides appropriate interface.
 *
 * The reason for introducing this object/class is that nm-iface-helper
 * needs NMRouteManager and NMDefaultRouteManager classes/objects which
 * in turn use NMNetnsController class/object which uses NMNetns class/
 * object which finally uses NMDevice class/object. But, NMDevice class/
 * object isn't used by nm-iface-helper.
 *
 * So, to not introduce dependency of nm-iface-helper on NMDevice, this
 * dummy class/object is introduced that breaks dependency chain
 * described in the previous paragraph.
 */

#include "config.h"

#include <gmodule.h>
#include <nm-dbus-interface.h>

#include "nm-platform.h"
#include "nm-linux-platform.h"
#include "nm-netns.h"
#include "nm-netns-controller.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMNetnsController, nm_netns_controller, G_TYPE_OBJECT)

typedef struct {
	NMNetns *netns;
} NMNetnsControllerPrivate;

#define NM_NETNS_CONTROLLER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS_CONTROLLER, NMNetnsControllerPrivate))

NM_DEFINE_SINGLETON_GETTER (NMNetnsController, nm_netns_controller_get, NM_TYPE_NETNS_CONTROLLER);

NMNetns *
nm_netns_controller_get_root_netns (void)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	return priv->netns;
}

/******************************************************************/

static void
nm_netns_controller_init (NMNetnsController *self)
{
}

static void
nm_netns_controller_class_init (NMNetnsControllerClass *klass)
{
	g_type_class_add_private (klass, sizeof (NMNetnsControllerPrivate));
}

