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
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>

#include "parser.h"
#include "plugin.h"

#include "nm-core-internal.h"
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>
#include <nm-setting-ppp.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-8021x.h>
#include <nm-system-config-interface.h>
#include <nm-utils.h>
#include <nm-logging.h>
#include <ctype.h>

gboolean
ofono_update_connection_from_context (NMConnection *connection,
                                      GHashTable *context,
                                      GError **error)
{
	NMSettingConnection *s_con;
	NMSettingGsm *s_gsm;
	gboolean success = FALSE;
	char *idstr = NULL;
	char *uuid_base = NULL;
	char *uuid = NULL;

	s_con = nm_connection_get_setting_connection (connection);
	if(!s_con) {
		s_con = NM_SETTING_CONNECTION (nm_setting_connection_new());
		g_assert (s_con);
		nm_connection_add_setting (connection, NM_SETTING (s_con));
	}

	idstr = g_strconcat ("/",
	                     g_hash_table_lookup (context, "IMSI"),
	                     "/",
	                     g_hash_table_lookup (context, "ID"),
	                     NULL);
	uuid_base = idstr;

	uuid = nm_utils_uuid_generate_from_string (uuid_base, -1, NM_UTILS_UUID_TYPE_LEGACY, NULL);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_GSM_SETTING_NAME,
	              NM_SETTING_CONNECTION_ID, idstr,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_READ_ONLY, TRUE,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NULL);
	g_free (uuid);

	/* GSM setting */
	s_gsm = NM_SETTING_GSM (nm_setting_gsm_new ());
	g_assert (s_gsm);
	nm_connection_add_setting (connection, NM_SETTING (s_gsm));

	/*
	 * oFono should already know how to handle placing the call, but NM
	 * insists on having a number. Pass the usual *99#.
	 */
	g_object_set (s_gsm, NM_SETTING_GSM_NUMBER, "*99#", NULL);

	nm_log_info (LOGD_SETTINGS, "SCPlugin-Ofono: "
	             "update_connection_setting_from_context: name:%s, path:%s, id:%s, uuid: %s",
	             (char *) g_hash_table_lookup (context, "Name"),
	             (char *) g_hash_table_lookup (context, "ID"),
	             idstr, nm_setting_connection_get_uuid (s_con));

	success = nm_connection_verify (connection, error);

	g_free (idstr);
	return success;
}
