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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef _NM_BLUEZ5_UTILS_H_
#define _NM_BLUEZ5_UTILS_H_

#include <glib.h>

gboolean nm_bluez5_dun_connect (const guint8 adapter[ETH_ALEN],
                                const guint8 remote[ETH_ALEN],
                                int *out_rfcomm_fd,
                                char **out_rfcomm_dev,
                                int *out_rfcomm_id,
                                GError **error);

void nm_bluez5_dun_cleanup (int sk, int rfcomm_id);

#endif  /* _NM_BLUEZ5_UTILS_H_ */
