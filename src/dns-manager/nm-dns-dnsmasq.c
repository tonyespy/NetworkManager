/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2010 Dan Williams <dcbw@redhat.com>
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
 */

#include "nm-default.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "nm-dns-dnsmasq.h"
#include "nm-utils.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dns-utils.h"
#include "nm-bus-manager.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMDnsDnsmasq, nm_dns_dnsmasq, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_DNSMASQ_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqPrivate))

#define PIDFILE NMRUNDIR "/dnsmasq.pid"
#define CONFFILE NMRUNDIR "/dnsmasq.conf"
#define CONFDIR NMCONFDIR "/dnsmasq.d"

#define DNSMASQ_DBUS_SERVICE "org.freedesktop.NetworkManager.dnsmasq"
#define DNSMASQ_DBUS_PATH "/uk/org/thekelleys/dnsmasq"

typedef struct {
	NMBusManager *dbus_mgr;
	GDBusConnection *connection;
	GDBusProxy *dnsmasq;
	gboolean running;

	GVariantBuilder *servers;
} NMDnsDnsmasqPrivate;

/*****************************************************************************/

#define _NMLOG_DOMAIN         LOGD_DNS
#define _NMLOG_PREFIX_NAME    "dnsmasq"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), _NMLOG_DOMAIN, \
                "%s[%p]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME, \
                (self) \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void
add_dnsmasq_nameserver (GVariantBuilder *servers,
                        const char *ip,
                        const char *domain)
{
	nm_log_dbg (LOGD_DNS, "Adding nameserver '%s' for domain '%s'",
	            ip, domain);

	g_return_if_fail (ip);

	g_variant_builder_open (servers, G_VARIANT_TYPE ("as"));

	if (domain)
		g_variant_builder_add (servers, "s", domain);
	g_variant_builder_add (servers, "s", ip);

	g_variant_builder_close (servers);
}

static gboolean
add_ip4_config (GVariantBuilder *servers, NMIP4Config *ip4, gboolean split)
{
	char buf[INET_ADDRSTRLEN];
	in_addr_t addr;
	int nnameservers, i_nameserver, n, i;
	gboolean added = FALSE;

	nnameservers = nm_ip4_config_get_num_nameservers (ip4);

	if (split) {
		char **domains, **iter;

		if (nnameservers == 0)
			return FALSE;

		for (i_nameserver = 0; i_nameserver < nnameservers; i_nameserver++) {
			addr = nm_ip4_config_get_nameserver (ip4, i_nameserver);
			nm_utils_inet4_ntop (addr, buf);

			/* searches are preferred over domains */
			n = nm_ip4_config_get_num_searches (ip4);
			for (i = 0; i < n; i++) {
				add_dnsmasq_nameserver (servers,
				                        buf,
				                        nm_ip4_config_get_search (ip4, i));
				added = TRUE;
			}

			if (n == 0) {
				/* If not searches, use any domains */
				n = nm_ip4_config_get_num_domains (ip4);
				for (i = 0; i < n; i++) {
					add_dnsmasq_nameserver (servers,
					                        buf,
					                        nm_ip4_config_get_domain (ip4, i));
					added = TRUE;
				}
			}

			/* Ensure reverse-DNS works by directing queries for in-addr.arpa
			 * domains to the split domain's nameserver.
			 */
			domains = nm_dns_utils_get_ip4_rdns_domains (ip4);
			if (domains) {
				for (iter = domains; iter && *iter; iter++)
					add_dnsmasq_nameserver (servers, buf, *iter);
				g_strfreev (domains);
				added = TRUE;
			}
		}
	}

	/* If no searches or domains, just add the namservers */
	if (!added) {
		for (i = 0; i < nnameservers; i++) {
			addr = nm_ip4_config_get_nameserver (ip4, i);
			add_dnsmasq_nameserver (servers,
			                        nm_utils_inet4_ntop (addr, NULL), NULL);
		}
	}

	return TRUE;
}

static char *
ip6_addr_to_string (const struct in6_addr *addr, const char *iface)
{
	char *buf;

	if (IN6_IS_ADDR_V4MAPPED (addr)) {
		/* inet_ntop is probably supposed to do this for us, but it doesn't */
		buf = g_malloc (INET_ADDRSTRLEN);
		nm_utils_inet4_ntop (addr->s6_addr32[3], buf);
	} else if (!iface || !iface[0] || !IN6_IS_ADDR_LINKLOCAL (addr)) {
		buf = g_malloc (INET6_ADDRSTRLEN);
		nm_utils_inet6_ntop (addr, buf);
	} else {
		/* If we got a scope identifier, we need use '%' instead of
		 * '@', since dnsmasq supports '%' in server= addresses
		 * only since version 2.58 and up
		 */
		buf = g_strconcat (nm_utils_inet6_ntop (addr, NULL), "@", iface, NULL);
	}
	return buf;
}

static void
add_global_config (GVariantBuilder *dnsmasq_servers, const NMGlobalDnsConfig *config)
{
	guint i, j;

	g_return_if_fail (config);

	for (i = 0; i < nm_global_dns_config_get_num_domains (config); i++) {
		NMGlobalDnsDomain *domain = nm_global_dns_config_get_domain (config, i);
		const char *const *servers = nm_global_dns_domain_get_servers (domain);
		const char *name = nm_global_dns_domain_get_name (domain);

		g_return_if_fail (name);

		for (j = 0; servers && servers[j]; j++) {
			if (!strcmp (name, "*"))
				add_dnsmasq_nameserver (dnsmasq_servers, servers[j], NULL);
			else
				add_dnsmasq_nameserver (dnsmasq_servers, servers[j], name);
		}

	}
}

static gboolean
add_ip6_config (GVariantBuilder *servers, NMIP6Config *ip6, gboolean split)
{
	const struct in6_addr *addr;
	char *buf = NULL;
	int nnameservers, i_nameserver, n, i;
	gboolean added = FALSE;
	const char *iface;

	nnameservers = nm_ip6_config_get_num_nameservers (ip6);

	iface = g_object_get_data (G_OBJECT (ip6), IP_CONFIG_IFACE_TAG);
	g_assert (iface);

	if (split) {
		if (nnameservers == 0)
			return FALSE;

		for (i_nameserver = 0; i_nameserver < nnameservers; i_nameserver++) {
			addr = nm_ip6_config_get_nameserver (ip6, i_nameserver);
			buf = ip6_addr_to_string (addr, iface);

			/* searches are preferred over domains */
			n = nm_ip6_config_get_num_searches (ip6);
			for (i = 0; i < n; i++) {
				add_dnsmasq_nameserver (servers,
				                        buf,
				                        nm_ip6_config_get_search (ip6, i));
				added = TRUE;
			}

			if (n == 0) {
				/* If not searches, use any domains */
				n = nm_ip6_config_get_num_domains (ip6);
				for (i = 0; i < n; i++) {
					add_dnsmasq_nameserver (servers,
					                        buf,
					                        nm_ip6_config_get_domain (ip6, i));
					added = TRUE;
				}
			}

			g_free (buf);
		}
	}

	/* If no searches or domains, just add the namservers */
	if (!added) {
		for (i = 0; i < nnameservers; i++) {
			addr = nm_ip6_config_get_nameserver (ip6, i);
			buf = ip6_addr_to_string (addr, iface);
			if (buf) {
				add_dnsmasq_nameserver (servers, buf, NULL);
				g_free (buf);
			}
		}
	}

	return TRUE;
}

static void
dnsmasq_update_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (user_data);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	GError *error = NULL;
	GVariant *response;

	response = g_dbus_proxy_call_finish (priv->dnsmasq, res, &error);
	if (error) {
		nm_log_warn (LOGD_DNS, "Dnsmasq update failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
	}

	if (response)
		g_variant_unref (response);
}

static gboolean
send_dnsmasq_update (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	nm_log_dbg (LOGD_DNS, "trying to update dnsmasq nameservers");

	if (!priv->servers) {
		nm_log_warn (LOGD_DNS, "no nameservers list to send update");
		return FALSE;
	}

	if (priv->running) {
		g_dbus_proxy_call (priv->dnsmasq,
		                   "SetServersEx",
		                   g_variant_new ("(aas)",
		                                  priv->servers),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   NULL,
		                   (GAsyncReadyCallback) dnsmasq_update_done,
		                   self);
		g_variant_builder_unref (priv->servers);
		priv->servers = NULL;
	} else {
		nm_log_warn (LOGD_DNS, "Dnsmasq not found on the bus.");
		nm_log_warn (LOGD_DNS, "The nameserver update will be sent when dnsmasq appears.");
	}

	return TRUE;
}

static void
name_owner_changed (GObject    *object,
                    GParamSpec *pspec,
                    gpointer    user_data)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (user_data);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	gs_free char *owner = NULL;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));
	if (owner) {
		nm_log_info (LOGD_DNS, "dnsmasq appeared as %s", owner);
		priv->running = TRUE;
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_APPEARED);
	} else {
		nm_log_info (LOGD_DNS, "dnsmasq disappeared");
		priv->running = FALSE;
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
	}
}

static void
dnsmasq_proxy_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (user_data);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	GError *error = NULL;
	gs_free char *owner = NULL;

	nm_log_dbg (LOGD_DNS, "dnsmasq proxy creation returned");

	if (priv->dnsmasq) {
		nm_log_dbg (LOGD_DNS, "already have an old proxy; replacing.");
		g_object_unref (priv->dnsmasq);
		priv->dnsmasq = NULL;
	}

	priv->dnsmasq = g_dbus_proxy_new_finish (res, &error);
	if (!priv->dnsmasq) {
		nm_log_warn (LOGD_DNS, "Failed to connect to dnsmasq via DBus: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
	} else {
		nm_log_dbg (LOGD_DNS, "dnsmasq proxy creation successful");

		g_signal_connect (priv->dnsmasq, "notify::g-name-owner",
				  G_CALLBACK (name_owner_changed), self);
		owner = g_dbus_proxy_get_name_owner (priv->dnsmasq);
		priv->running = (owner != NULL);

		if (priv->running && priv->servers)
			send_dnsmasq_update (self);
	}
}

static void
get_dnsmasq_proxy (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	g_return_if_fail (!priv->dnsmasq);

	nm_log_dbg (LOGD_DNS, "retrieving dnsmasq proxy");

	if (!priv->dnsmasq) {
		g_dbus_proxy_new (priv->connection,
		                  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
		                  NULL,
		                  DNSMASQ_DBUS_SERVICE,
		                  DNSMASQ_DBUS_PATH,
		                  DNSMASQ_DBUS_SERVICE,
		                  NULL,
		                  dnsmasq_proxy_cb,
		                  self);
	}
}

static gboolean
start_dnsmasq (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	const char *dm_binary;
	const char *argv[15];
	GError *error = NULL;
	int ignored;
	GPid pid = 0;
	guint idx = 0;
	GString *conf;

	/* dnsmasq is probably already started; if it's the case, don't do
	 * anything more.
	 */
	if (priv->running) {
		nm_log_dbg (LOGD_DNS, "dnsmasq is already running");
		return TRUE;
	}

	/* Start dnsmasq */

	dm_binary = nm_utils_find_helper ("dnsmasq", DNSMASQ_PATH, NULL);
	if (!dm_binary) {
		_LOGW ("could not find dnsmasq binary");
		return FALSE;
	}

	/* Build up the new dnsmasq config file */
	conf = g_string_sized_new (150);

	/* Write out the config file */
	if (!g_file_set_contents (CONFFILE, conf->str, -1, &error)) {
		_LOGW ("failed to write dnsmasq config file %s: %s",
		       CONFFILE,
		       error->message);
		g_clear_error (&error);
		goto out;
	}
	ignored = chmod (CONFFILE, 0644);

	_LOGD ("dnsmasq local caching DNS configuration:");
	_LOGD ("%s", conf->str);

	argv[idx++] = dm_binary;
	argv[idx++] = "--no-resolv";  /* Use only commandline */
	argv[idx++] = "--keep-in-foreground";
	argv[idx++] = "--no-hosts"; /* don't use /etc/hosts to resolve */
	argv[idx++] = "--bind-interfaces";
	argv[idx++] = "--pid-file=" PIDFILE;
	argv[idx++] = "--listen-address=127.0.0.1"; /* Should work for both 4 and 6 */
	argv[idx++] = "--conf-file=" CONFFILE;
	argv[idx++] = "--cache-size=400";
	argv[idx++] = "--proxy-dnssec"; /* Allow DNSSEC to pass through */
	argv[idx++] = "--enable-dbus=" DNSMASQ_DBUS_SERVICE;

	/* dnsmasq exits if the conf dir is not present */
	if (g_file_test (CONFDIR, G_FILE_TEST_IS_DIR))
		argv[idx++] = "--conf-dir=" CONFDIR;

	argv[idx++] = NULL;
	g_warn_if_fail (idx <= G_N_ELEMENTS (argv));

	/* And finally spawn dnsmasq */
	pid = nm_dns_plugin_child_spawn (NM_DNS_PLUGIN (self), argv, PIDFILE, "bin/dnsmasq");

	if (pid && !priv->dnsmasq)
		get_dnsmasq_proxy (self);
out:
	g_string_free (conf, TRUE);
	return pid ? TRUE : FALSE;
}

static gboolean
update (NMDnsPlugin *plugin,
        const GSList *vpn_configs,
        const GSList *dev_configs,
        const GSList *other_configs,
        const NMGlobalDnsConfig *global_config,
        const char *hostname)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	GSList *iter;
	gboolean ret = FALSE;

	if (!priv->running)
		start_dnsmasq (self);

	if (priv->servers)
		g_variant_builder_unref (priv->servers);
	priv->servers = g_variant_builder_new (G_VARIANT_TYPE ("aas"));

	if (global_config)
		add_global_config (priv->servers, global_config);
	else {
		/* Use split DNS for VPN configs */
		for (iter = (GSList *) vpn_configs; iter; iter = g_slist_next (iter)) {
			if (NM_IS_IP4_CONFIG (iter->data))
				add_ip4_config (priv->servers, NM_IP4_CONFIG (iter->data), TRUE);
			else if (NM_IS_IP6_CONFIG (iter->data))
				add_ip6_config (priv->servers, NM_IP6_CONFIG (iter->data), TRUE);
		}

		/* Now add interface configs without split DNS */
		for (iter = (GSList *) dev_configs; iter; iter = g_slist_next (iter)) {
			if (NM_IS_IP4_CONFIG (iter->data))
				add_ip4_config (priv->servers, NM_IP4_CONFIG (iter->data), FALSE);
			else if (NM_IS_IP6_CONFIG (iter->data))
				add_ip6_config (priv->servers, NM_IP6_CONFIG (iter->data), FALSE);
		}

		/* And any other random configs */
		for (iter = (GSList *) other_configs; iter; iter = g_slist_next (iter)) {
			if (NM_IS_IP4_CONFIG (iter->data))
				add_ip4_config (priv->servers, NM_IP4_CONFIG (iter->data), FALSE);
			else if (NM_IS_IP6_CONFIG (iter->data))
				add_ip6_config (priv->servers, NM_IP6_CONFIG (iter->data), FALSE);
		}
	}

	ret = send_dnsmasq_update (self);

	/* If all the configs lists are empty, there is just nothing to be caching --
	 * we cleared up the dnsmasq cache; but we should also fail the update, so
	 * that we don't write 127.0.0.1 to resolv.conf.
	 */
	if (((vpn_configs && g_slist_length ((GSList *) vpn_configs) < 1) || !vpn_configs) &&
	    ((dev_configs && g_slist_length ((GSList *) dev_configs) < 1) || !dev_configs) &&
	    ((other_configs && g_slist_length ((GSList *) other_configs) < 1) || !other_configs))
		ret = FALSE;

	return ret;
}

/****************************************************************/

static const char *
dm_exit_code_to_msg (int status)
{
	if (status == 1)
		return "Configuration problem";
	else if (status == 2)
		return "Network access problem (address in use; permissions; etc)";
	else if (status == 3)
		return "Filesystem problem (missing file/directory; permissions; etc)";
	else if (status == 4)
		return "Memory allocation failure";
	else if (status == 5)
		return "Other problem";
	else if (status >= 11)
		return "Lease-script 'init' process failure";
	return "Unknown error";
}

static void
child_quit (NMDnsPlugin *plugin, gint status)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	gboolean failed = TRUE;
	int err;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err) {
			_LOGW ("dnsmasq exited with error: %s (%d)",
			       dm_exit_code_to_msg (err),
			       err);
		} else
			failed = FALSE;
	} else if (WIFSTOPPED (status))
		_LOGW ("dnsmasq stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("dnsmasq died with signal %d", WTERMSIG (status));
	else
		_LOGW ("dnsmasq died from an unknown cause");
	unlink (CONFFILE);

	if (failed)
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
}

/****************************************************************/

static gboolean
is_caching (NMDnsPlugin *plugin)
{
	return TRUE;
}

static const char *
get_name (NMDnsPlugin *plugin)
{
	return "dnsmasq";
}

/****************************************************************/

NMDnsPlugin *
nm_dns_dnsmasq_new (void)
{
	return g_object_new (NM_TYPE_DNS_DNSMASQ, NULL);
}

static void
nm_dns_dnsmasq_init (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	priv->dbus_mgr = nm_bus_manager_get ();
	priv->running = FALSE;

	g_assert (priv->dbus_mgr);

	priv->connection = nm_bus_manager_get_connection (priv->dbus_mgr);
	if (!priv->connection)
		nm_log_warn (LOGD_DNS, "Could not get the system bus to speak to dnsmasq.");
	else
		get_dnsmasq_proxy (self);
}

static void
dispose (GObject *object)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (object);

	unlink (CONFFILE);

	if (priv->dbus_mgr) {
		g_object_unref (priv->dbus_mgr);
		priv->dbus_mgr = NULL;
	}

	G_OBJECT_CLASS (nm_dns_dnsmasq_parent_class)->dispose (object);
}

static void
nm_dns_dnsmasq_class_init (NMDnsDnsmasqClass *dns_class)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (dns_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dns_class);

	g_type_class_add_private (dns_class, sizeof (NMDnsDnsmasqPrivate));

	object_class->dispose = dispose;

	plugin_class->child_quit = child_quit;
	plugin_class->is_caching = is_caching;
	plugin_class->update = update;
	plugin_class->get_name = get_name;
}

