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

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#include <glib.h>
#include <glib/gi18n.h>

#include "nm-dns-dnsmasq.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dns-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-manager.h"

G_DEFINE_TYPE (NMDnsDnsmasq, nm_dns_dnsmasq, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_DNSMASQ_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqPrivate))

#define PIDFILE "/run/sendsigs.omit.d/network-manager.dnsmasq.pid"
#define CONFFILE NMRUNDIR "/dnsmasq.conf"
#define CONFDIR NMCONFDIR "/dnsmasq.d"

#define DNSMASQ_DBUS_SERVICE "org.freedesktop.NetworkManager.dnsmasq"
#define DNSMASQ_DBUS_PATH "/uk/org/thekelleys/dnsmasq"
#define DNSMASQ_DBUS_INTERFACE "uk.org.thekelleys.dnsmasq"

typedef struct {
	NMDBusManager *dbus_mgr;
	guint name_owner_id;
} NMDnsDnsmasqPrivate;

/*******************************************/

static gboolean
add_ip4_config (DBusMessage *message, NMIP4Config *ip4, gboolean split)
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
			addr = g_htonl(nm_ip4_config_get_nameserver (ip4, i_nameserver));
			dbus_message_append_args (message,
			                          DBUS_TYPE_UINT32, &addr,
			                          DBUS_TYPE_INVALID);

			/* searches are preferred over domains */
			n = nm_ip4_config_get_num_searches (ip4);
			for (i = 0; i < n; i++) {
				char *search = nm_ip4_config_get_search (ip4, i);
				dbus_message_append_args (message,
				                          DBUS_TYPE_STRING, &search,
				                          DBUS_TYPE_INVALID);
				added = TRUE;
			}

			if (n == 0) {
				/* If not searches, use any domains */
				n = nm_ip4_config_get_num_domains (ip4);
				for (i = 0; i < n; i++) {
					char *domain = nm_ip4_config_get_domain (ip4, i);
					dbus_message_append_args (message,
					                          DBUS_TYPE_STRING, &domain,
					                          DBUS_TYPE_INVALID);
					added = TRUE;
				}
			}

			/* Ensure reverse-DNS works by directing queries for in-addr.arpa
			 * domains to the split domain's nameserver.
			 */
			domains = nm_dns_utils_get_ip4_rdns_domains (ip4);
			if (domains) {
				for (iter = domains; iter && *iter; iter++)
					dbus_message_append_args (message,
					                          DBUS_TYPE_STRING, &(*iter),
					                          DBUS_TYPE_INVALID);
				g_strfreev (domains);
				added = TRUE;
			}
		}
	}

	/* If no searches or domains, just add the namservers */
	if (!added) {
		for (i = 0; i < nnameservers; i++) {
			addr = g_htonl (nm_ip4_config_get_nameserver (ip4, i));
			dbus_message_append_args (message,
			                          DBUS_TYPE_UINT32, &addr,
			                          DBUS_TYPE_INVALID);
		}
	}

	return TRUE;
}

static gboolean
add_ip6_config (DBusMessage *message, NMIP6Config *ip6, gboolean split)
{
	const struct in6_addr *addr;
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
			dbus_message_append_args (message,
			                          DBUS_TYPE_BYTE, &addr->s6_addr[0],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[1],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[2],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[3],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[4],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[5],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[6],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[7],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[8],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[9],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[10],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[11],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[12],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[13],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[14],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[15],
			                          DBUS_TYPE_INVALID);

			/* searches are preferred over domains */
			n = nm_ip6_config_get_num_searches (ip6);
			for (i = 0; i < n; i++) {
				char *search = nm_ip6_config_get_search (ip6, i);
				dbus_message_append_args (message,
				                          DBUS_TYPE_STRING, &search,
				                          DBUS_TYPE_INVALID);
				added = TRUE;
			}

			if (n == 0) {
				/* If not searches, use any domains */
				n = nm_ip6_config_get_num_domains (ip6);
				for (i = 0; i < n; i++) {
					char *domain = nm_ip6_config_get_domain (ip6, i);
					dbus_message_append_args (message,
					                          DBUS_TYPE_STRING, &domain,
					                          DBUS_TYPE_INVALID);
					added = TRUE;
				}
			}
		}
	}

	/* If no searches or domains, just add the namservers */
	if (!added) {
		for (i = 0; i < nnameservers; i++) {
			addr = nm_ip6_config_get_nameserver (ip6, i);
			dbus_message_append_args (message,
			                          DBUS_TYPE_BYTE, &addr->s6_addr[0],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[1],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[2],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[3],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[4],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[5],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[6],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[7],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[8],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[9],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[10],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[11],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[12],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[13],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[14],
			                          DBUS_TYPE_BYTE, &addr->s6_addr[15],
			                          DBUS_TYPE_INVALID);
		}
	}

	return TRUE;
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
	char *dnsmasq_owner;
	GString *conf;

	/* dnsmasq is probably already started; if it's the case, don't do
	 * anything more.
	 */
	dnsmasq_owner = nm_dbus_manager_get_name_owner (priv->dbus_mgr, DNSMASQ_DBUS_SERVICE, NULL);
	if (dnsmasq_owner != NULL)
		return TRUE;

	/* Start dnsmasq */

	dm_binary = nm_utils_find_helper ("dnsmasq", DNSMASQ_PATH, NULL);
	if (!dm_binary) {
		nm_log_warn (LOGD_DNS, "Could not find dnsmasq binary");
		return FALSE;
	}

	/* Build up the new dnsmasq config file */
	conf = g_string_sized_new (150);

	/* Write out the config file */
	if (!g_file_set_contents (CONFFILE, conf->str, -1, &error)) {
		nm_log_warn (LOGD_DNS, "Failed to write dnsmasq config file %s: (%d) %s",
		             CONFFILE,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		goto out;
	}
	ignored = chmod (CONFFILE, 0644);

	nm_log_dbg (LOGD_DNS, "dnsmasq local caching DNS configuration:");
	nm_log_dbg (LOGD_DNS, "%s", conf->str);

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

out:
	g_string_free (conf, TRUE);
	return pid ? TRUE : FALSE;
}

static gboolean
update (NMDnsPlugin *plugin,
        const GSList *vpn_configs,
        const GSList *dev_configs,
        const GSList *other_configs,
        const char *hostname)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	DBusConnection *connection;
	DBusMessage *message;
	GSList *iter;
	GError *error = NULL;
	gboolean have_dnsmasq = FALSE;
	gboolean ret = FALSE;
	dbus_bool_t result;

	have_dnsmasq = start_dnsmasq (self);
	if (!have_dnsmasq)
		goto out;

	connection = nm_dbus_manager_get_dbus_connection (priv->dbus_mgr);
	if (!connection) {
		nm_log_warn (LOGD_DNS, "Could not get the system bus to speak to dnsmasq.");
		goto out;
	}

	message = dbus_message_new_method_call (DNSMASQ_DBUS_SERVICE, DNSMASQ_DBUS_PATH,
	                                        DNSMASQ_DBUS_INTERFACE, "SetServers");

	/* Use split DNS for VPN configs */
	for (iter = (GSList *) vpn_configs; iter; iter = g_slist_next (iter)) {
		if (NM_IS_IP4_CONFIG (iter->data))
			add_ip4_config (message, NM_IP4_CONFIG (iter->data), TRUE);
		else if (NM_IS_IP6_CONFIG (iter->data))
			add_ip6_config (message, NM_IP6_CONFIG (iter->data), TRUE);
	}

	/* Now add interface configs without split DNS */
	for (iter = (GSList *) dev_configs; iter; iter = g_slist_next (iter)) {
		if (NM_IS_IP4_CONFIG (iter->data))
			add_ip4_config (message, NM_IP4_CONFIG (iter->data), FALSE);
		else if (NM_IS_IP6_CONFIG (iter->data))
			add_ip6_config (message, NM_IP6_CONFIG (iter->data), FALSE);
	}

	/* And any other random configs */
	for (iter = (GSList *) other_configs; iter; iter = g_slist_next (iter)) {
		if (NM_IS_IP4_CONFIG (iter->data))
			add_ip4_config (message, NM_IP4_CONFIG (iter->data), FALSE);
		else if (NM_IS_IP6_CONFIG (iter->data))
			add_ip6_config (message, NM_IP6_CONFIG (iter->data), FALSE);
	}

	if (!nm_dbus_manager_get_name_owner (priv->dbus_mgr, DNSMASQ_DBUS_SERVICE, &error)) {
		nm_log_warn (LOGD_DNS, "dnsmasq not available on the bus, can't update servers.");
		if (error)
			nm_log_err (LOGD_DNS, "dnsmasq owner not found on bus: %s", error->message);
		goto out;
	}

	dbus_message_set_no_reply (message, TRUE);

	result = dbus_connection_send (connection, message, NULL);
	if (!result) {
		nm_log_err (LOGD_DNS, "Could not send dnsmasq SetServers method.");
		goto out;
	}

	ret = TRUE;

	/* If all the configs lists are empty, there is just nothing to be caching --
	 * we cleared up the dnsmasq cache; but we should also fail the update, so
	 * that we don't write 127.0.0.1 to resolv.conf.
	 */
	if (((vpn_configs && g_slist_length (vpn_configs) < 1) || !vpn_configs) &&
	    ((dev_configs && g_slist_length (dev_configs) < 1) || !dev_configs) &&
	    ((other_configs && g_slist_length (other_configs) < 1) || !other_configs))
		ret = FALSE;

out:
	if (message)
		dbus_message_unref (message);

	return ret;
}

/****************************************************************/

static void
name_owner_changed_cb (NMDBusManager *dbus_mgr,
                       const char *name,
                       const char *old_owner,
                       const char *new_owner,
                       gpointer user_data)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (user_data);
	gboolean old_owner_good = (old_owner && strlen (old_owner));
	gboolean new_owner_good = (new_owner && strlen (new_owner));

	/* Can't handle the signal if its not from dnsmasq */
	if (strcmp (DNSMASQ_DBUS_SERVICE, name))
		return;

	if (!old_owner_good && new_owner_good) {
		nm_log_warn (LOGD_DNS, "dnsmasq appeared on DBus: %s",
		             new_owner);
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_APPEARED);
	} else if (old_owner_good && new_owner_good) {
		nm_log_dbg (LOGD_DNS, "DBus name owner for dnsmasq changed: %s -> %s",
		             old_owner, new_owner);
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_APPEARED);
	} else {
		nm_log_warn (LOGD_DNS, "dnsmasq disappeared from the bus.");
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
	}
}

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
			nm_log_warn (LOGD_DNS, "dnsmasq exited with error: %s (%d)",
			             dm_exit_code_to_msg (err),
			             err);
		} else
			failed = FALSE;
	} else if (WIFSTOPPED (status)) {
		nm_log_warn (LOGD_DNS, "dnsmasq stopped unexpectedly with signal %d", WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_warn (LOGD_DNS, "dnsmasq died with signal %d", WTERMSIG (status));
	} else {
		nm_log_warn (LOGD_DNS, "dnsmasq died from an unknown cause");
	}
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

	priv->dbus_mgr = nm_dbus_manager_get ();

	g_assert (priv->dbus_mgr);

	priv->name_owner_id = g_signal_connect (priv->dbus_mgr,
	                                        NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
	                                        G_CALLBACK (name_owner_changed_cb),
	                                        self);
}

static void
dispose (GObject *object)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (object);

	unlink (CONFFILE);

	if (priv->dbus_mgr) {
		if (priv->name_owner_id)
			g_signal_handler_disconnect (priv->dbus_mgr, priv->name_owner_id);
		g_object_unref (priv->dbus_mgr);
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

