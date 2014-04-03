/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-gdhcp.c - gdhcp specific hooks for NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
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

#include <glib.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <config.h>

#include "nm-gdhcp.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "gdhcp.h"
#include "nm-dhcp-utils.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMGdhcp, nm_gdhcp, NM_TYPE_DHCP_CLIENT)

#define NM_GDHCP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_GDHCP, NMGdhcpPrivate))

typedef struct {
	GDHCPClient *dhcp_client;
	GDHCPType dhcp_type;
	char *lease_file;

	guint rt;  /* msec */
	guint timeout_id;
	guint request_count;

	gboolean privacy;
} NMGdhcpPrivate;

/************************************************************/

GSList *
nm_gdhcp_get_lease_ip_configs (const char *iface,
                               const char *uuid,
                               gboolean ipv6)
{
	GSList *leases = NULL;

	return leases;
}

static guint
log_domain (GDHCPType dhcp_type)
{
	switch (dhcp_type) {
	case G_DHCP_IPV4:
		return LOGD_DHCP4;
	case G_DHCP_IPV6:
		return LOGD_DHCP6;
	case G_DHCP_IPV4LL:
		return LOGD_AUTOIP4;
	default:
		break;
	}
	g_assert_not_reached ();
}

static void
dhcp_debug (const char *str, void *data)
{
	nm_log_dbg (log_domain (NM_GDHCP_GET_PRIVATE (data)->dhcp_type),
	            "(%s): %s",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (data)),
	            str);
}

/************************************************************/

#define G_DHCP_TIME_OFFSET         2
#define G_DHCP_INTERFACE_MTU      26
#define G_DHCP_BROADCAST_ADDRESS  28
#define G_DHCP_STATIC_ROUTES      33
#define G_DHCP_NIS_DOMAIN         40
#define G_DHCP_NIS_SERVERS        41
#define G_DHCP_DHCP_SERVER_ID     54
#define G_DHCP_DOMAIN_SEARCH     119
#define G_DHCP_RFC3442_ROUTES    121
#define G_DHCP_MS_ROUTES         249
#define G_DHCP_WPAD              252

/* Internal values */
#define DHCP_IP_ADDRESS         1024
#define DHCP_EXPIRY             1025
#define DHCP6_IP6_ADDRESS       1026
#define DHCP6_IP6_PREFIXLEN     1027
#define DHCP6_PREFERRED_LIFE    1028
#define DHCP6_MAX_LIFE          1029
#define DHCP6_STARTS            1030
#define DHCP6_LIFE_STARTS       1031
#define DHCP6_RENEW             1032
#define DHCP6_REBIND            1033
#define DHCP6_IAID              1034

typedef struct {
	guint num;
	const char *desc;
	gboolean include;
} ReqOption;

#define REQPREFIX "requested_"

static const ReqOption dhcp4_requests[] = {
	{ G_DHCP_HOST_NAME,         REQPREFIX "host_name",                       TRUE },
	{ G_DHCP_SUBNET,            REQPREFIX "subnet_mask",                     TRUE },
	{ G_DHCP_DNS_SERVER,        REQPREFIX "domain_name_servers",             TRUE },
	{ G_DHCP_DOMAIN_NAME,       REQPREFIX "domain_name",                     TRUE },
	{ G_DHCP_NTP_SERVER,        REQPREFIX "ntp_servers",                     TRUE },
	{ G_DHCP_LEASE_TIME,        REQPREFIX "expiry",                          TRUE },
	{ G_DHCP_ROUTER,            REQPREFIX "routers",                         TRUE },
	{ G_DHCP_TIME_OFFSET,       REQPREFIX "time_offset",                     TRUE },
	{ G_DHCP_INTERFACE_MTU,     REQPREFIX "interface_mtu",                   TRUE },
	{ G_DHCP_BROADCAST_ADDRESS, REQPREFIX "broadcast_address",               TRUE },
	{ G_DHCP_STATIC_ROUTES,     REQPREFIX "static_routes",                   TRUE },
	{ G_DHCP_NIS_DOMAIN,        REQPREFIX "nis_domain",                      TRUE },
	{ G_DHCP_NIS_SERVERS,       REQPREFIX "nis_servers",                     TRUE },
	{ G_DHCP_DHCP_SERVER_ID,    REQPREFIX "dhcp_server_identifier",          TRUE },
	{ G_DHCP_DOMAIN_SEARCH,     REQPREFIX "domain_search",                   TRUE },
	{ G_DHCP_RFC3442_ROUTES,    REQPREFIX "rfc3442_classless_static_routes", TRUE },
	{ G_DHCP_MS_ROUTES,         REQPREFIX "ms_classless_static_routes",      TRUE },
	{ G_DHCP_WPAD,              REQPREFIX "wpad",                            TRUE },

	/* Internal values */
	{ DHCP_IP_ADDRESS,          REQPREFIX "ip_address",                      FALSE },
	{ 0, NULL, FALSE }
};

/* NOTE: update g_dhcpv6_client_set_oro() when adding/removing items */
static const ReqOption dhcp6_requests[] = {
	{ G_DHCPV6_CLIENTID,     REQPREFIX "dhcp6_client_id",     TRUE },

	/* Don't request server ID by default; some servers don't reply to
	 * Information Requests that request the Server ID.
	 */
	{ G_DHCPV6_SERVERID,     REQPREFIX "dhcp6_server_id",     FALSE },

	{ G_DHCPV6_DNS_SERVERS,  REQPREFIX "dhcp6_name_servers",  TRUE },
	{ G_DHCPV6_DOMAIN_LIST,  REQPREFIX "dhcp6_domain_search", TRUE },
	{ G_DHCPV6_SNTP_SERVERS, REQPREFIX "dhcp6_sntp_servers",  TRUE },

	/* Internal values */
	{ DHCP6_IP6_ADDRESS,     REQPREFIX "ip6_address",         FALSE },
	{ DHCP6_IP6_PREFIXLEN,   REQPREFIX "ip6_prefixlen",       FALSE },
	{ DHCP6_PREFERRED_LIFE,  REQPREFIX "preferred_life",      FALSE },
	{ DHCP6_MAX_LIFE,        REQPREFIX "max_life",            FALSE },
	{ DHCP6_STARTS,          REQPREFIX "starts",              FALSE },
	{ DHCP6_LIFE_STARTS,     REQPREFIX "life_starts",         FALSE },
	{ DHCP6_RENEW,           REQPREFIX "renew",               FALSE },
	{ DHCP6_REBIND,          REQPREFIX "rebind",              FALSE },
	{ DHCP6_IAID,            REQPREFIX "iaid",                FALSE },
	{ 0, NULL, FALSE }
};

static void
take_option (GHashTable *options,
             const ReqOption *requests,
             guint option,
             char *value)
{
	guint i;

	g_return_if_fail (value != NULL);

	for (i = 0; requests[i].desc; i++) {
		if (requests[i].num == option) {
			g_hash_table_insert (options,
			                     (gpointer) (requests[i].desc + STRLEN (REQPREFIX)),
			                     value);
			break;
		}
	}
	/* Option should always be found */
	g_assert (requests[i].desc);
}

static void
add_option (GHashTable *options, const ReqOption *requests, guint option, const char *value)
{
	take_option (options, requests, option, g_strdup (value));
}

static void
add_option_u32 (GHashTable *options, const ReqOption *requests, guint option, guint32 value)
{
	take_option (options, requests, option, g_strdup_printf ("%u", value));
}

static void
add_requests_to_options (GHashTable *options, const ReqOption *requests)
            
{
	guint i;

	for (i = 0; requests[i].desc; i++) {
		if (requests[i].include)
			g_hash_table_insert (options, (gpointer) requests[i].desc, g_strdup ("1"));
	}
}

static void
add_requests_to_dhcp (GDHCPClient *dhcp_client, const ReqOption *requests)
            
{
	guint i;

	for (i = 0; requests[i].desc; i++) {
		if (requests[i].include)
			g_dhcp_client_set_request (dhcp_client, requests[i].num);
	}

	if (g_dhcp_client_get_type (dhcp_client) == G_DHCP_IPV6) {
		/* NOTE: update this when adding/removing from dhcp6_requests */
		g_dhcpv6_client_set_oro (dhcp_client, 3,
		                         G_DHCPV6_DNS_SERVERS,
		                         G_DHCPV6_DOMAIN_LIST,
		                         G_DHCPV6_SNTP_SERVERS);
	}
}

/************************************************************/

/* Transmission params in msec, RFC 3315 chapter 5.5 */
#define INF_MAX_DELAY   (1 * 1000)
#define INF_TIMEOUT     (1 * 1000)
#define INF_MAX_RT      (120 * 1000)
#define SOL_MAX_DELAY   (1 * 1000)
#define SOL_TIMEOUT     (1 * 1000)
#define SOL_MAX_RT      (120 * 1000)
#define REQ_TIMEOUT     (1 * 1000)
#define REQ_MAX_RT      (30 * 1000)
#define REQ_MAX_RC      10
#define REN_TIMEOUT     (10 * 1000)
#define REN_MAX_RT      (600 * 1000)
#define REB_TIMEOUT     (10 * 1000)
#define REB_MAX_RT      (600 * 1000)
#define CNF_MAX_DELAY   (1 * 1000)
#define CNF_TIMEOUT     (1 * 1000)
#define CNF_MAX_RT      (4 * 1000)
#define CNF_MAX_RD      (10 * 1000)
#define DEC_TIMEOUT     (1 * 1000)
#define DEC_MAX_RC      5

static void
clear_timeout (NMGdhcp *self)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	if (priv->timeout_id) {
		g_source_remove (priv->timeout_id);
		priv->timeout_id = 0;
	}
}

/* Return a randomization factor in the range [-0.1, 0.1].  See
 * RFC 3315 section 14.
 */
static inline double
RAND (void)
{
	return g_random_double_range (-0.1, 0.1);
}

static void
set_timeout (NMGdhcp *self,
             guint irt,
             guint mrt,
             gboolean force_positive,
             GSourceFunc callback)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	double tmp = RAND ();

	clear_timeout (self);

	/* See RFC 3315 chapter 14 */
	if (irt) {
		/* RT for Solicitation messages (eg, while waiting for Advertise
		 * messages) must be positive.  RFC 3315 chapter 17.1.2.
		 */
		if (force_positive)
			tmp = ABS (tmp);

		/* RT = IRT + RAND*IRT */
		priv->rt = irt + (guint) (tmp * (gdouble) irt);
	} else {
		/* Retransmission; RT = 2*RTprev + RAND*RTprev */
		gdouble rt_prev = (gdouble) priv->rt;

		priv->rt = (guint) ((2.0 * rt_prev) + (tmp * rt_prev));
	}

	if (mrt && (priv->rt > mrt))
		priv->rt = mrt + (guint) (RAND () * (gdouble) mrt);

	priv->timeout_id = g_timeout_add (priv->rt, callback, self);
}

/************************************************************/

static void
clear_callbacks (GDHCPClient *dhcp_client)
{
	static const GDHCPClientEvent events[] = {
		G_DHCP_CLIENT_EVENT_LEASE_AVAILABLE,
		G_DHCP_CLIENT_EVENT_IPV4LL_AVAILABLE,
		G_DHCP_CLIENT_EVENT_NO_LEASE,
		G_DHCP_CLIENT_EVENT_LEASE_LOST,
		G_DHCP_CLIENT_EVENT_IPV4LL_LOST,
		G_DHCP_CLIENT_EVENT_ADDRESS_CONFLICT,
		G_DHCP_CLIENT_EVENT_INFORMATION_REQ,
		G_DHCP_CLIENT_EVENT_SOLICITATION,
		G_DHCP_CLIENT_EVENT_ADVERTISE,
		G_DHCP_CLIENT_EVENT_REQUEST,
		G_DHCP_CLIENT_EVENT_RENEW,
		G_DHCP_CLIENT_EVENT_REBIND,
		G_DHCP_CLIENT_EVENT_RELEASE,
		G_DHCP_CLIENT_EVENT_CONFIRM,
		G_DHCP_CLIENT_EVENT_DECLINE,
	};
	guint i;

	for (i = 0; i < G_N_ELEMENTS (events); i++)
		g_dhcp_client_register_event (dhcp_client, events[i], NULL, NULL);
}

/************************************************************/

static void
lease4_available_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMIP4Config *ip4_config = NULL;
	GHashTable *options;
	GList *iter, *option = NULL;
	char buf[INET_ADDRSTRLEN];
	const char *str;
	guint32 tmp_addr, gwaddr = 0, plen = 0;
	NMPlatformIP4Address address;
	GString *l;
	guint32 expiry;
	long int tmp_num;

	nm_log_dbg (LOGD_DHCP4, "(%s): lease available",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	str = g_dhcp_client_get_address (dhcp_client);
	if (!str || (inet_pton (AF_INET, str, &tmp_addr) < 1)) {
		nm_log_warn (LOGD_DHCP4, "(%s): failed to read address from lease",
		             nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	options = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

	memset (&address, 0, sizeof (address));
	address.address = tmp_addr;
	nm_log_info (LOGD_DHCP4, "  address %s", str);
	add_option (options, dhcp4_requests, DHCP_IP_ADDRESS, str);

	option = g_dhcp_client_get_option (dhcp_client, G_DHCP_SUBNET);
	if (option && (inet_pton (AF_INET, option->data, &tmp_addr) > 0)) {
		plen = nm_utils_ip4_netmask_to_prefix (tmp_addr);
		nm_log_info (LOGD_DHCP4, "  plen %d (%s)",
		             plen,
		             (const char *) option->data);
	} else {
		/* Get default netmask for the IP according to appropriate class. */
		plen = nm_utils_ip4_get_default_prefix (address.address);
		nm_log_info (LOGD_DHCP4, "  plen %d (default)", plen);
	}
	address.plen = plen;

	tmp_addr = nm_utils_ip4_prefix_to_netmask (plen);
	if (inet_ntop (AF_INET, &tmp_addr, buf, sizeof (buf)) > 0)
		add_option (options, dhcp4_requests, G_DHCP_SUBNET, buf);

	ip4_config = nm_ip4_config_new ();

	option = g_dhcp_client_get_option (dhcp_client, G_DHCP_ROUTER);
	if (option) {
		str = (const char *) option->data;
		if (inet_pton (AF_INET, str, &gwaddr) > 0) {
			nm_ip4_config_set_gateway (ip4_config, gwaddr);
			nm_log_info (LOGD_DHCP4, "  gateway %s", str);
			add_option (options, dhcp4_requests, G_DHCP_ROUTER, str);
		} else
			nm_log_warn (LOGD_DHCP4, "ignoring invalid gateway '%s'", str);
	}

	/* Lease time */
	expiry = 3600; /* one hour */
	option = g_dhcp_client_get_option (dhcp_client, G_DHCP_LEASE_TIME);
	if (option) {
		errno = 0;
		tmp_num = strtol (option->data, NULL, 10);
		if (tmp_num > 0 && tmp_num <= G_MAXUINT32 && errno == 0)
			expiry = (guint32) tmp_num;
	} else
		nm_log_warn (LOGD_DHCP4, "no lease expiry found!");
	add_option_u32 (options, dhcp4_requests, G_DHCP_LEASE_TIME, (guint) MIN (time (NULL) + expiry, G_MAXUINT32));

	address.timestamp = nm_utils_get_monotonic_timestamp_s ();
	address.lifetime = address.preferred = (guint32) expiry;
	address.source = NM_PLATFORM_SOURCE_DHCP;
	nm_ip4_config_add_address (ip4_config, &address);

	option = g_dhcp_client_get_option (dhcp_client, G_DHCP_DNS_SERVER);
	l = g_string_sized_new (30);
	for (iter = option; iter; iter = iter->next) {
		str = (const char *) iter->data;
		if (inet_pton (AF_INET, str, &tmp_addr) > 0) {
			nm_ip4_config_add_nameserver (ip4_config, tmp_addr);
			nm_log_info (LOGD_DHCP4, "  nameserver '%s'", str);
			g_string_append_printf (l, "%s%s", l->len ? " " : "", str);
		} else
			nm_log_warn (LOGD_DHCP4, "ignoring invalid nameserver '%s'", str);
	}
	if (l->len)
		add_option (options, dhcp4_requests, G_DHCP_DNS_SERVER, l->str);
	g_string_free (l, TRUE);

	option = g_dhcp_client_get_option (dhcp_client, G_DHCP_DOMAIN_NAME);
	if (option) {
		/* Multiple domains sometimes stuffed into the option */
		char **domains = g_strsplit (option->data, " ", 0);
		char **s;

		for (s = domains; *s; s++) {
			nm_log_info (LOGD_DHCP4, "  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (domains);
		add_option (options, dhcp4_requests, G_DHCP_DOMAIN_NAME, option->data);
	}

	option = g_dhcp_client_get_option (dhcp_client, G_DHCP_HOST_NAME);
	if (option) {
		str = (const char *) option->data;
		nm_log_info (LOGD_DHCP4, "  hostname '%s'", str);
		add_option (options, dhcp4_requests, G_DHCP_HOST_NAME, str);
	}

	add_requests_to_options (options, dhcp4_requests);

	nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
	                          NM_DHCP_STATE_BOUND,
	                          G_OBJECT (ip4_config),
	                          options);
	g_hash_table_destroy (options);
	g_object_unref (ip4_config);
}

static void
no_lease_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_TIMEOUT, NULL, NULL);
}

static void
lease_lost_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_FAIL, NULL, NULL);
}

static gboolean
ip4_start (NMDHCPClient *client,
           const char *dhcp_client_id,
           GByteArray *dhcp_anycast_addr,
           const char *hostname)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (client);
	GDHCPClientError error;
	int err;

	priv->dhcp_type = G_DHCP_IPV4;
	priv->dhcp_client = g_dhcp_client_new (priv->dhcp_type,
	                                       nm_dhcp_client_get_ifindex (client),
	                                       &error);
	if (error != G_DHCP_CLIENT_ERROR_NONE) {
		nm_log_warn (LOGD_DHCP4,
		             "(%s): error creating DHCP client: %d",
		             nm_dhcp_client_get_iface (client),
		             error);
		return FALSE;
	}

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_DHCP4))
		g_dhcp_client_set_debug (priv->dhcp_client, dhcp_debug, client);

	g_dhcp_client_set_id (priv->dhcp_client);

	if (hostname)
		g_dhcp_client_set_send (priv->dhcp_client, G_DHCP_HOST_NAME, hostname);

	add_requests_to_dhcp (priv->dhcp_client, dhcp4_requests);

	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_LEASE_AVAILABLE,
	                              lease4_available_cb,
	                              client);
	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_LEASE_LOST,
	                              lease_lost_cb,
	                              client);
	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_NO_LEASE,
	                              no_lease_cb,
	                              client);

	err = g_dhcp_client_start (priv->dhcp_client, NULL);
	return (err == 0);
}

/************************************************************/

static gboolean rebind_start (gpointer user_data);
static gboolean renew_start (gpointer user_data);
static gboolean expire_check (NMGdhcp *self);

static gboolean
build_ip6_config (GDHCPClient *dhcp_client,
                  const char *iface,
                  NMIP6Config **out_ip6_config,
                  GHashTable **out_options)
{
	NMIP6Config *ip6_config;
	GHashTable *options;
	GString *l;
	const char *str;
	GList *option, *iter;
	struct in6_addr tmp_addr;
	NMPlatformIP6Address address;
	guint32 renew = 0, rebind = 0, preferred = 0, valid = 0, iaid;
	gint32 start = 0;
	const unsigned char *duid;
	int duid_len = 0;
	GByteArray *tmp;
	guint32 epoch_start;

	g_return_val_if_fail (dhcp_client, FALSE);
	g_return_val_if_fail (out_ip6_config, FALSE);
	g_return_val_if_fail (out_options, FALSE);

	/* Address */
	option = g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_NA);
	if (!option)
		option = g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_TA);
	if (!option || (inet_pton (AF_INET6, option->data, &tmp_addr) < 0)) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to read address from lease", iface);
		return FALSE;
	}

	if (g_dhcpv6_client_get_timeouts (dhcp_client, &renew, &rebind, &start, &preferred, &valid) != 0) {
		nm_log_warn (LOGD_DHCP6, "(%s): failed to read lifetime from lease", iface);
		return FALSE;
	}

	options = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
	ip6_config = nm_ip6_config_new ();

	memset (&address, 0, sizeof (address));
	address.address = tmp_addr;
	address.plen = 128;
	nm_log_info (LOGD_DHCP6, "  address %s/%d", (const char *) option->data, address.plen);
	add_option (options, dhcp6_requests, DHCP6_IP6_ADDRESS, (const char *) option->data);
	add_option_u32 (options, dhcp6_requests, DHCP6_IP6_PREFIXLEN, address.plen);

	address.timestamp = start;
	epoch_start = time (NULL) - (nm_utils_get_monotonic_timestamp_s () - start);
	add_option_u32 (options, dhcp6_requests, DHCP6_STARTS, epoch_start);
	add_option_u32 (options, dhcp6_requests, DHCP6_LIFE_STARTS, epoch_start);

	/* Preferred/Valid times */
	address.lifetime = valid;
	add_option_u32 (options, dhcp6_requests, DHCP6_MAX_LIFE, address.lifetime);
	address.preferred = MIN (preferred, valid - 1);
	add_option_u32 (options, dhcp6_requests, DHCP6_PREFERRED_LIFE, address.preferred);

	add_option_u32 (options, dhcp6_requests, DHCP6_RENEW, renew);
	add_option_u32 (options, dhcp6_requests, DHCP6_REBIND, rebind);

	address.source = NM_PLATFORM_SOURCE_DHCP;
	nm_ip6_config_add_address (ip6_config, &address);

	/* DNS servers */
	l = g_string_sized_new (30);
	option = g_dhcp_client_get_option (dhcp_client, G_DHCPV6_DNS_SERVERS);
	for (iter = option; iter; iter = iter->next) {
		str = (const char *) iter->data;
		if (inet_pton (AF_INET6, str, &tmp_addr) > 0) {
			nm_ip6_config_add_nameserver (ip6_config, &tmp_addr);
			nm_log_info (LOGD_DHCP6, "  nameserver '%s'", str);
			g_string_append_printf (l, "%s%s", l->len ? " " : "", str);
		} else
			nm_log_warn (LOGD_DHCP6, "ignoring invalid nameserver '%s'", str);
	}
	if (l->len)
		add_option (options, dhcp6_requests, G_DHCPV6_DNS_SERVERS, l->str);
	g_string_free (l, TRUE);

	/* Domain searches */
	option = g_dhcp_client_get_option (dhcp_client, G_DHCPV6_DOMAIN_LIST);
	l = g_string_sized_new (30);
	for (iter = option; iter; iter = iter->next) {
		str = (const char *) iter->data;
		nm_log_info (LOGD_DHCP6, "  domain '%s'", str);
		g_string_append_printf (l, "%s%s", l->len ? " " : "", str);
	}
	if (l->len)
		g_hash_table_insert (options, "domain_search", l->str);
	g_string_free (l, TRUE);

	/* Time servers */
	option = g_dhcp_client_get_option (dhcp_client, G_DHCPV6_SNTP_SERVERS);
	l = g_string_sized_new (30);
	for (iter = option; iter; iter = iter->next) {
		str = (const char *) iter->data;
		if (inet_pton (AF_INET6, str, &tmp_addr) > 0) {
			nm_log_info (LOGD_DHCP6, "  SNTP server '%s'", str);
			g_string_append_printf (l, "%s%s", l->len ? " " : "", str);
		} else
			nm_log_warn (LOGD_DHCP6, "ignoring invalid SNTP server '%s'", str);
	}
	if (l->len)
		add_option (options, dhcp6_requests, G_DHCPV6_DOMAIN_LIST, l->str);
	g_string_free (l, TRUE);

	option = g_dhcp_client_get_option (dhcp_client, G_DHCPV6_SNTP_SERVERS);

	/* Server ID */
	duid = g_dhcpv6_client_get_server_duid (dhcp_client, &duid_len);
	if (duid && (duid_len > 0)) {
		tmp = g_byte_array_sized_new (duid_len);
		g_byte_array_append (tmp, duid, duid_len);
		take_option (options,
		             dhcp6_requests,
		             G_DHCPV6_SERVERID,
		             nm_dhcp_utils_duid_to_string (tmp));
		g_byte_array_free (tmp, TRUE);
	}

	/* Client ID */
	duid = g_dhcpv6_client_get_client_duid (dhcp_client, &duid_len);
	if (duid && (duid_len > 0)) {
		tmp = g_byte_array_sized_new (duid_len);
		g_byte_array_append (tmp, duid, duid_len);
		take_option (options,
		             dhcp6_requests,
		             G_DHCPV6_CLIENTID,
		             nm_dhcp_utils_duid_to_string (tmp));
		g_byte_array_free (tmp, TRUE);
	}

	/* IAID */
	iaid = g_dhcpv6_client_get_iaid (dhcp_client);
	if (iaid) {
		take_option (options,
		             dhcp6_requests,
		             DHCP6_IAID,
		             g_strdup_printf ("%02x:%02x:%02x:%02x",
		                              (guint8) ((iaid >> 24) & 0xFF),
		                              (guint8) ((iaid >> 16) & 0xFF),
		                              (guint8) ((iaid >> 8)  & 0xFF),
		                              (guint8) (iaid         & 0xFF)));
	}

	add_requests_to_options (options, dhcp6_requests);

	*out_ip6_config = ip6_config;
	*out_options = options;
	return TRUE;
}

static void
handle_bound (NMGdhcp *self,
              GDHCPClient *dhcp_client,
              const char *event,
              gboolean maybe_renew)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	uint16_t status;
	NMIP6Config *ip6_config = NULL;
	GHashTable *options = NULL;
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));

	status = g_dhcpv6_client_get_status (dhcp_client);
	if (status) {
		nm_log_warn (LOGD_DHCP6, "(%s): %s failure status %u", iface, event, status);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	if (!build_ip6_config (dhcp_client, iface, &ip6_config, &options)) {
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	g_dhcpv6_client_reset_request (priv->dhcp_client);

	nm_dhcp_client_set_state (NM_DHCP_CLIENT (self),
	                          NM_DHCP_STATE_BOUND,
	                          G_OBJECT (ip6_config),
	                          options);
	g_hash_table_destroy (options);
	g_object_unref (ip6_config);

	if (maybe_renew) {
		guint32 renew, rebind, valid, tmp;
		gint32 start, now;

		g_dhcpv6_client_get_timeouts (dhcp_client, &renew, &rebind, &start, NULL, &valid);
		now = nm_utils_get_monotonic_timestamp_s ();
		nm_log_dbg (LOGD_DHCP6, "(%s): timeouts renew %u rebind %u valid %u now %d start %d",
		            iface, renew, rebind, valid, now, start);

		if (expire_check (self)) {
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
			return;
		}

		renew = MIN (valid >> 1, renew ? renew : 1800);
		rebind = MIN (valid * 0.875, rebind ? rebind : 3600);

		g_assert (priv->timeout_id == 0);
		if (now >= start + rebind) {
			/* Past rebind time, rebind immediately */
			nm_log_dbg (LOGD_DHCP6, "(%s): rebind time passed, starting rebind", iface);
			priv->timeout_id = g_idle_add (rebind_start, self);
		} else if (now < start + renew) {
			/* Before renew time */
			tmp = (start + renew) - now;
			nm_log_dbg (LOGD_DHCP6, "(%s): scheduling renew in %u seconds", iface, tmp);
			priv->timeout_id = g_timeout_add_seconds (tmp, renew_start, self);
		} else {
			/* Between renew time and rebind time */
			tmp = (start + rebind) - now;
			nm_log_dbg (LOGD_DHCP6, "(%s): scheduling rebind in %u seconds", iface, tmp);
			priv->timeout_id = g_timeout_add_seconds (tmp, rebind_start, self);
		}
	}
}

/*********************************/

static GDHCPClient *client6_create (NMGdhcp *self);

static void
info_req_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);

	nm_log_dbg (LOGD_DHCP6, "(%s): information request reply received",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	g_dhcpv6_client_clear_retransmit (dhcp_client);
	clear_timeout (self);

	handle_bound (self, dhcp_client, "info-request", FALSE);
}

static gboolean
inforeq_timeout_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	nm_log_dbg (LOGD_DHCP6, "(%s): timeout waiting for information request reply; retrying...",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	/* MRC = MRD = 0; retransmit forever; RFC 3315 chapter 18.1.5 */
	priv->timeout_id = 0;
	set_timeout (self, 0, INF_MAX_RT, FALSE, inforeq_timeout_cb);
	g_dhcpv6_client_set_retransmit (priv->dhcp_client);
	g_dhcp_client_start (priv->dhcp_client, NULL);
	return G_SOURCE_REMOVE;
}

static gboolean
inforeq_delay_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	nm_log_dbg (LOGD_DHCP6, "(%s): sending initial DHCPv6 information request",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	priv->timeout_id = 0;
	set_timeout (self, INF_TIMEOUT, INF_MAX_RT, FALSE, inforeq_timeout_cb);

	if (g_dhcp_client_start (priv->dhcp_client, NULL) != 0)
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);

	return G_SOURCE_REMOVE;
}

static gboolean
info_only_start (NMGdhcp *self, guint delay_ms)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	if (priv->dhcp_client)
		g_dhcp_client_unref (priv->dhcp_client);

	priv->dhcp_client = client6_create (self);
	if (!priv->dhcp_client)
		return FALSE;

	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_INFORMATION_REQ,
	                              info_req_cb,
	                              self);
	if (delay_ms)
		priv->timeout_id = g_timeout_add (delay_ms, inforeq_delay_cb, self);
	else
		inforeq_delay_cb (self);

	return TRUE;
}

/*********************************/

static gboolean request_timeout_cb (gpointer user_data);
static gboolean request_send (NMGdhcp *self, gboolean add_addresses);
static gboolean solicitation_start (NMGdhcp *self, guint delay_ms);
static gboolean rebind_send (NMGdhcp *self);
static gboolean renew_send (NMGdhcp *self);

static gboolean
expire_check (NMGdhcp *self)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	gint32 start, now;
	guint32 expire;

	now = nm_utils_get_monotonic_timestamp_s ();
	g_dhcpv6_client_get_timeouts (priv->dhcp_client, NULL, NULL, &start, NULL, &expire);
	if (now >= start + expire) {
		nm_log_dbg (LOGD_DHCP6, "(%s): all addresses expired",
		            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));
		return TRUE;
	}
	return FALSE;
}

static gboolean
renew_timeout_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	guint32 rebind;
	gint32 start, now;

	priv->timeout_id = 0;

	if (expire_check (self)) {
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return G_SOURCE_REMOVE;
	}

	nm_log_dbg (LOGD_DHCP6, "(%s): DHCPv6 renew timed out; retrying...",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	now = nm_utils_get_monotonic_timestamp_s ();
	g_dhcpv6_client_get_timeouts (priv->dhcp_client, NULL, &rebind, &start, NULL, NULL);
	if (now >= start + rebind) {
		/* Start rebind if past rebind time */
		rebind_start (self);
	} else {
		set_timeout (self, 0, REB_MAX_RT, FALSE, renew_timeout_cb);

		g_dhcpv6_client_set_retransmit (priv->dhcp_client);
		if (g_dhcp_client_start (priv->dhcp_client, NULL) != 0)
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
	}

	return G_SOURCE_REMOVE;
}

static void
renew_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));
	uint16_t status;
	gboolean resend = FALSE;

	g_dhcpv6_client_clear_retransmit (dhcp_client);
	clear_timeout (self);

	status = g_dhcpv6_client_get_status (dhcp_client);

	nm_log_dbg (LOGD_DHCP6, "(%s): renew reply received (status %d)", iface, status);

	/* RFC 3315, 18.1.8 handle the resend if error */
	switch (status) {
	case G_DHCPV6_ERROR_MCAST:
		resend = TRUE;
		break;
	case G_DHCPV6_ERROR_SUCCESS:
		if (   g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_NA)
			|| g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_TA)) {
			/* Success! */
			handle_bound (self, dhcp_client, "renew", TRUE);
		} else {
			/* If no IA was received, retry the request */
			resend = TRUE;
		}
		break;
	default:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	}

	if (resend) {
		nm_log_dbg (LOGD_DHCP6, "(%s): resending DHCPv6 renew", iface);
		if (!renew_send (self))
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
	}
}

static gboolean
renew_send (NMGdhcp *self)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	uint32_t renew, rebind;

	clear_callbacks (priv->dhcp_client);
	g_dhcp_client_clear_requests (priv->dhcp_client);
	add_requests_to_dhcp (priv->dhcp_client, dhcp6_requests);
	g_dhcp_client_set_request (priv->dhcp_client, G_DHCPV6_SERVERID);

	g_dhcpv6_client_get_timeouts (priv->dhcp_client, &renew, &rebind, NULL, NULL, NULL);
	g_dhcpv6_client_set_ia (priv->dhcp_client,
	                        nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                        priv->privacy ? G_DHCPV6_IA_TA : G_DHCPV6_IA_NA,
	                        &renew, &rebind, FALSE, NULL);
	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_RENEW,
	                              renew_cb,
	                              self);
	return (g_dhcp_client_start (priv->dhcp_client, NULL) == 0);
}

static gboolean
renew_start (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	g_dhcpv6_client_clear_retransmit (priv->dhcp_client);

	priv->timeout_id = 0;

	if (expire_check (self)) {
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return G_SOURCE_REMOVE;
	}

	nm_log_dbg (LOGD_DHCP6, "(%s): sending renew request",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	set_timeout (self, REN_TIMEOUT, REN_MAX_RT, FALSE, renew_timeout_cb);
	if (!renew_send (self))
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
	return G_SOURCE_REMOVE;
}

static gboolean
rebind_timeout_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	priv->timeout_id = 0;

	if (expire_check (self)) {
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return G_SOURCE_REMOVE;
	}

	nm_log_dbg (LOGD_DHCP6, "(%s): DHCPv6 rebind timed out; retrying...",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	set_timeout (self, 0, REB_MAX_RT, FALSE, rebind_timeout_cb);

	g_dhcpv6_client_set_retransmit (priv->dhcp_client);

	if (g_dhcp_client_start (priv->dhcp_client, NULL) != 0)
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);

	return G_SOURCE_REMOVE;
}

static void
rebind_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));
	uint16_t status;
	gboolean resend = FALSE;

	g_dhcpv6_client_clear_retransmit (dhcp_client);
	clear_timeout (self);

	status = g_dhcpv6_client_get_status (dhcp_client);

	nm_log_dbg (LOGD_DHCP6, "(%s): rebind reply received (status %d)", iface, status);

	/* RFC 3315, 18.1.8 handle the resend if error */
	switch (status) {
	case G_DHCPV6_ERROR_MCAST:
		resend = TRUE;
		break;
	case G_DHCPV6_ERROR_SUCCESS:
		if (   g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_NA)
			|| g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_TA)) {
			/* Success! */
			handle_bound (self, dhcp_client, "rebind", TRUE);
		} else {
			/* If no IA was received, retry the request */
			resend = TRUE;
		}
		break;
	default:
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	}

	if (resend) {
		nm_log_dbg (LOGD_DHCP6, "(%s): resending DHCPv6 rebind", iface);
		if (!rebind_send (self))
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
	}
}

static gboolean
rebind_send (NMGdhcp *self)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	clear_callbacks (priv->dhcp_client);
	g_dhcp_client_clear_requests (priv->dhcp_client);
	add_requests_to_dhcp (priv->dhcp_client, dhcp6_requests);

	g_dhcpv6_client_set_ia (priv->dhcp_client,
	                        nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                        priv->privacy ? G_DHCPV6_IA_TA : G_DHCPV6_IA_NA,
	                        NULL, NULL, TRUE, NULL);
	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_REBIND,
	                              rebind_cb,
	                              self);
	return (g_dhcp_client_start (priv->dhcp_client, NULL) == 0);
}

static gboolean
rebind_start (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	g_dhcpv6_client_clear_retransmit (priv->dhcp_client);

	priv->timeout_id = 0;

	if (expire_check (self)) {
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		return G_SOURCE_REMOVE;
	}

	nm_log_dbg (LOGD_DHCP6, "(%s): sending rebind request",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	set_timeout (self, REB_TIMEOUT, REB_MAX_RT, FALSE, rebind_timeout_cb);
	if (!rebind_send (self))
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);

	return G_SOURCE_REMOVE;
}

/* Returns TRUE if the request should be resent */
static gboolean
request_handle_timeout (NMGdhcp *self, GSourceFunc callback)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	if (priv->request_count >= REQ_MAX_RC) {
		nm_log_warn (LOGD_DHCP6, "(%s): max request timeouts reached",
		             nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));
		priv->request_count = 0;
		return FALSE;
	}

	priv->request_count++;
	set_timeout (self, 0, REQ_MAX_RT, FALSE, callback);
	g_dhcpv6_client_set_retransmit (priv->dhcp_client);
	return TRUE;
}

static gboolean
request_resend_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	priv->timeout_id = 0;
	set_timeout (self, 0, REQ_MAX_RT, FALSE, request_timeout_cb);

	nm_log_dbg (LOGD_DHCP6, "(%s): resending DHCPv6 request after failure",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	if (!g_dhcp_client_start (priv->dhcp_client, NULL))
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);

	return G_SOURCE_REMOVE;
}

static void
request_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));
	uint16_t status;

	g_dhcpv6_client_reset_request (dhcp_client);
	g_dhcpv6_client_clear_retransmit (dhcp_client);

	clear_timeout (self);

	status = g_dhcpv6_client_get_status (dhcp_client);

	nm_log_dbg (LOGD_DHCP6, "(%s): request reply received (status %d)", iface, status);

	/* RFC 3315, 18.1.8 handle the resend if error */
	switch (status) {
	case G_DHCPV6_ERROR_MCAST:
		nm_log_dbg (LOGD_DHCP6, "(%s): resending DHCPv6 request", iface);
		if (!request_send (self, TRUE))
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		break;
	case G_DHCPV6_ERROR_LINK:
		solicitation_start (self, 0);
		break;
	case G_DHCPV6_ERROR_FAILURE:
		/* Rate limit the resend of request message */
		if (!request_handle_timeout (self, request_resend_cb))
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_TIMEOUT, NULL, NULL);
		break;
	default:
		if (status != G_DHCPV6_ERROR_SUCCESS) {
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
			break;
		}

		if (   g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_NA)
			|| g_dhcp_client_get_option (dhcp_client, G_DHCPV6_IA_TA)) {
			/* Success! */
			handle_bound (self, dhcp_client, "request", TRUE);
		} else {
			/* If no IA was received, retry the request */
			if (!request_send (self, TRUE))
				nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
		}
		break;
	}
}

static gboolean
request_send (NMGdhcp *self, gboolean add_addresses)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	uint32_t renew, rebind;

	clear_callbacks (priv->dhcp_client);
	g_dhcp_client_clear_requests (priv->dhcp_client);
	add_requests_to_dhcp (priv->dhcp_client, dhcp6_requests);
	g_dhcp_client_set_request (priv->dhcp_client, G_DHCPV6_SERVERID);

	g_dhcpv6_client_get_timeouts (priv->dhcp_client, &renew, &rebind, NULL, NULL, NULL);
	g_dhcpv6_client_set_ia (priv->dhcp_client,
	                        nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
	                        priv->privacy ? G_DHCPV6_IA_TA : G_DHCPV6_IA_NA,
	                        &renew, &rebind,
	                        add_addresses,
	                        NULL);
	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_REQUEST,
	                              request_cb,
	                              self);
	return (g_dhcp_client_start (priv->dhcp_client, NULL) == 0);
}

static gboolean
request_timeout_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	priv->timeout_id = 0;
	if (request_handle_timeout (self, request_timeout_cb)) {
		nm_log_dbg (LOGD_DHCP6, "(%s): DHCPv6 request timed out; retrying...",
		            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

		if (!g_dhcp_client_start (priv->dhcp_client, NULL))
			nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
	} else
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_TIMEOUT, NULL, NULL);

	return G_SOURCE_REMOVE;
}

static void
advertise_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	uint16_t status;
	const char *iface = nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self));

	nm_log_dbg (LOGD_DHCP6, "(%s): advertise reply received", iface);

	g_dhcpv6_client_clear_retransmit (dhcp_client);
	clear_timeout (self);

	status = g_dhcpv6_client_get_status (dhcp_client);
	if (status) {
		nm_log_warn (LOGD_DHCP6, "(%s): advertise failure status %u", iface, status);
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (user_data), NM_DHCP_STATE_FAIL, NULL, NULL);
		return;
	}

	/* FIXME: RFC 3315 chapter 17.1.2 states that during the first RT the
	 * client should collect all Advertise messages, and only when the RT
	 * expires does the client pick the server with the highest Preference
	 * option to request a lease from.  gdhcp does not yet support this.
	 */

	set_timeout (self, REQ_TIMEOUT, REQ_MAX_RT, FALSE, request_timeout_cb);
	priv->request_count = 1;

	nm_log_dbg (LOGD_DHCP6, "(%s): sending initial DHCPv6 request", iface);

	if (!request_send (self, TRUE))
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);
}


static void
solicitation_cb (GDHCPClient *dhcp_client, gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);

	/* Server supports Rapid Commit and we have a lease */
	nm_log_dbg (LOGD_DHCP6, "(%s): solicitation reply received",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	g_dhcpv6_client_clear_retransmit (dhcp_client);
	clear_timeout (self);

	handle_bound (self, dhcp_client, "solicit", TRUE);
}

static gboolean
solicit_timeout_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	nm_log_dbg (LOGD_DHCP6, "(%s): solicitation timeout; retrying...",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	priv->timeout_id = 0;
	set_timeout (self, 0, SOL_MAX_RT, FALSE, solicit_timeout_cb);

	g_dhcpv6_client_set_retransmit (priv->dhcp_client);

	if (g_dhcp_client_start (priv->dhcp_client, NULL) != 0)
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);

	return G_SOURCE_REMOVE;
}

static gboolean
solicit_delay_cb (gpointer user_data)
{
	NMGdhcp *self = NM_GDHCP (user_data);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	nm_log_dbg (LOGD_DHCP6, "(%s): sending initial DHCPv6 solicitation",
	            nm_dhcp_client_get_iface (NM_DHCP_CLIENT (self)));

	priv->timeout_id = 0;
	set_timeout (self, INF_TIMEOUT, INF_MAX_RT, TRUE, solicit_timeout_cb);

	if (g_dhcp_client_start (priv->dhcp_client, NULL) != 0)
		nm_dhcp_client_set_state (NM_DHCP_CLIENT (self), NM_DHCP_STATE_FAIL, NULL, NULL);

	return G_SOURCE_REMOVE;
}

static gboolean
solicitation_start (NMGdhcp *self, guint delay_ms)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);

	if (priv->dhcp_client)
		g_dhcp_client_unref (priv->dhcp_client);

	priv->dhcp_client = client6_create (self);
	if (!priv->dhcp_client)
		return FALSE;

	g_dhcp_client_set_request (priv->dhcp_client, G_DHCPV6_RAPID_COMMIT);
	g_dhcpv6_client_set_ia (priv->dhcp_client,
		                    nm_dhcp_client_get_ifindex (NM_DHCP_CLIENT (self)),
		                    priv->privacy ? G_DHCPV6_IA_TA : G_DHCPV6_IA_NA,
		                    NULL, NULL, FALSE, NULL);

	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_SOLICITATION,
	                              solicitation_cb,
	                              self);

	g_dhcp_client_register_event (priv->dhcp_client,
	                              G_DHCP_CLIENT_EVENT_ADVERTISE,
	                              advertise_cb,
	                              self);

	if (delay_ms)
		priv->timeout_id = g_timeout_add (delay_ms, solicit_delay_cb, self);
	else
		solicit_delay_cb (self);

	return TRUE;
}

/*********************************/

static GDHCPClient *
client6_create (NMGdhcp *self)
{
	NMDHCPClient *client = NM_DHCP_CLIENT (self);
	GDHCPClientError error;
	GDHCPClient *dhcp_client = NULL;
	const GByteArray *duid;

	dhcp_client = g_dhcp_client_new (G_DHCP_IPV6,
	                                 nm_dhcp_client_get_ifindex (client),
	                                 &error);
	if (error != G_DHCP_CLIENT_ERROR_NONE) {
		nm_log_warn (LOGD_DHCP6, "(%s): error creating DHCP client: %d",
		             nm_dhcp_client_get_iface (client),
		             error);
		return NULL;
	}

	if (nm_logging_enabled (LOGL_DEBUG, LOGD_DHCP6))
		g_dhcp_client_set_debug (dhcp_client, dhcp_debug, self);

	duid = nm_dhcp_client_get_duid (client);
	g_assert (duid);
	g_dhcpv6_client_set_duid (dhcp_client, duid->data, duid->len);

	add_requests_to_dhcp (dhcp_client, dhcp6_requests);

	return dhcp_client;
}

static gboolean
ip6_start (NMDHCPClient *client,
           GByteArray *dhcp_anycast_addr,
           const char *hostname,
           gboolean info_only,
           NMSettingIP6ConfigPrivacy privacy,
           const GByteArray *duid)
{
	NMGdhcp *self = NM_GDHCP (client);
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (self);
	guint delay_ms;
	gboolean success;

	priv->dhcp_type = G_DHCP_IPV6;
	priv->privacy = (privacy == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);

	if (info_only) {
		/* Initial Information-Request delay; RFC 3315 chapter 18.1.5 */
		delay_ms = g_random_int_range (0, INF_MAX_DELAY);
		success = info_only_start (self, delay_ms);
	} else {
		/* Initial Solicitation delay; RFC 3315 chapter 17.1.2 */
		delay_ms = g_random_int_range (0, SOL_MAX_DELAY);
		success = solicitation_start (self, delay_ms);
	}

	if (success) {
		nm_log_dbg (LOGD_DHCP6, "(%s): delaying initial DHCPv6 request for %ums",
		            nm_dhcp_client_get_iface (client),
		            delay_ms);
	}
	return success;
}

static void
stop (NMDHCPClient *client, gboolean release, const GByteArray *duid)
{
	clear_timeout (NM_GDHCP (client));
	g_dhcp_client_stop (NM_GDHCP_GET_PRIVATE (client)->dhcp_client, release);
}

/***************************************************/

static void
nm_gdhcp_init (NMGdhcp *self)
{
}

static void
dispose (GObject *object)
{
	NMGdhcpPrivate *priv = NM_GDHCP_GET_PRIVATE (object);

	g_free (priv->lease_file);

	clear_timeout (NM_GDHCP (object));
	if (priv->dhcp_client) {
		clear_callbacks (priv->dhcp_client);
		g_dhcp_client_stop (priv->dhcp_client, FALSE);
		g_dhcp_client_unref (priv->dhcp_client);
		priv->dhcp_client = NULL;
	}

	G_OBJECT_CLASS (nm_gdhcp_parent_class)->dispose (object);
}

static void
nm_gdhcp_class_init (NMGdhcpClass *gdhcp_class)
{
	NMDHCPClientClass *client_class = NM_DHCP_CLIENT_CLASS (gdhcp_class);
	GObjectClass *object_class = G_OBJECT_CLASS (gdhcp_class);

	g_type_class_add_private (gdhcp_class, sizeof (NMGdhcpPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
}

