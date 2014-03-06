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

/***
    Parts of this file come from Avahi:

    avahi is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation; either version 2.1 of the
    License, or (at your option) any later version.

    avahi is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
    Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with avahi; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
    USA.
***/

#include "config.h"

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <netpacket/packet.h>

#include "nm-logging.h"
#include "nm-utils.h"
#include "nm-ip4ll.h"

G_DEFINE_TYPE (NMIP4ll, nm_ip4ll, G_TYPE_OBJECT)

typedef enum State {
	STATE_UNKNOWN,
    STATE_WAITING_PROBE,
    STATE_PROBING,
    STATE_WAITING_ANNOUNCE,
    STATE_ANNOUNCING,
    STATE_RUNNING,
    STATE_SLEEPING,
    STATE_MAX
} State;

struct _NMIP4llPrivate {
	int ifindex;
	guint8 hwaddr[NM_UTILS_HWADDR_LEN_MAX];
	guint hwaddr_len;

	guint timeout_id;
	guint event_id;
	GIOChannel *channel;

	State state;
	guint n_iteration;
	guint n_conflict;
};

#define NM_IP4LL_IFINDEX "ifindex"
#define NM_IP4LL_HWADDR  "hwaddr"

enum {
	PROP_0,
	PROP_IFINDEX,
	PROP_HWADDR,
	LAST_PROP
};

/*****************************************************************/

/* An implementation of RFC 3927 */

/* Constants from the RFC */
#define PROBE_WAIT 1
#define PROBE_NUM 3
#define PROBE_MIN 1
#define PROBE_MAX 2
#define ANNOUNCE_WAIT 2
#define ANNOUNCE_NUM 2
#define ANNOUNCE_INTERVAL 2
#define MAX_CONFLICTS 10
#define RATE_LIMIT_INTERVAL 60
#define DEFEND_INTERVAL 10

#define IPV4LL_NETWORK 0xA9FE0000L
#define IPV4LL_NETMASK 0xFFFF0000L
#define IPV4LL_HOSTMASK 0x0000FFFFL
#define IPV4LL_BROADCAST 0xA9FEFFFFL

#define ETHER_ADDRLEN 6
#define ETHER_HDR_SIZE (2+2*ETHER_ADDRLEN)
#define ARP_PACKET_SIZE (8+4+4+2*ETHER_ADDRLEN)

typedef enum Event {
    EVENT_NULL,
    EVENT_PACKET,
    EVENT_TIMEOUT,
    EVENT_REFRESH_REQUEST
} Event;

typedef enum ArpOperation {
    ARP_REQUEST = 1,
    ARP_RESPONSE = 2
} ArpOperation;

typedef struct ArpPacketInfo {
    ArpOperation operation;

    uint32_t sender_ip_address, target_ip_address;
    uint8_t sender_hw_address[ETHER_ADDRLEN], target_hw_address[ETHER_ADDRLEN];
} ArpPacketInfo;

typedef struct ArpPacket {
    uint8_t *ether_header;
    uint8_t *ether_payload;
} ArpPacket;

static gboolean
is_ll_address (guint32 addr)
{
    return
        ((ntohl(addr) & IPV4LL_NETMASK) == IPV4LL_NETWORK) &&
        ((ntohl(addr) & 0x0000FF00) != 0x0000) &&
        ((ntohl(addr) & 0x0000FF00) != 0xFF00);
}

static guint32
pick_addr (guint32 old_addr)
{
    guint32 addr;

    do {
        guint r = (guint) rand ();

        /* Reduce to 16 bits */
        while (r > 0xFFFF)
            r = (r >> 16) ^ (r & 0xFFFF);

        addr = htonl (IPV4LL_NETWORK | (guint32) r);

    } while (addr == old_addr || !is_ll_address (addr));

    return addr;
}

/*
 * Allocate a buffer with two pointers in front, one of which is
 * guaranteed to point ETHER_HDR_SIZE bytes into it.
 */
static ArpPacket *
packet_new (size_t packet_len)
{
    ArpPacket *p;
    guint8 *b;

    g_assert (packet_len > 0);

    b = g_malloc0 (sizeof (struct ArpPacket) + packet_len);
    p = (ArpPacket*) b;
    p->ether_header = NULL;
    p->ether_payload = b + sizeof (struct ArpPacket);

    return p;
}

static ArpPacket *
packet_new_with_info (const ArpPacketInfo *info, size_t *packet_len)
{
    ArpPacket *p = NULL;
    guint8 *r;

    g_assert (info);
    g_assert (info->operation == ARP_REQUEST || info->operation == ARP_RESPONSE);
    g_assert (packet_len != NULL);

    *packet_len = ARP_PACKET_SIZE;
    p = packet_new(*packet_len);
    r = p->ether_payload;

    r[1] = 1; /* HTYPE */
    r[2] = 8; /* PTYPE */
    r[4] = ETHER_ADDRLEN; /* HLEN */
    r[5] = 4; /* PLEN */
    r[7] = (uint8_t) info->operation;

    memcpy(r+8, info->sender_hw_address, ETHER_ADDRLEN);
    memcpy(r+14, &info->sender_ip_address, 4);
    memcpy(r+18, info->target_hw_address, ETHER_ADDRLEN);
    memcpy(r+24, &info->target_ip_address, 4);

    return p;
}

static ArpPacket *
packet_new_probe (uint32_t ip_address, const uint8_t*hw_address, size_t *packet_len)
{
    ArpPacketInfo info;

    memset(&info, 0, sizeof(info));
    info.operation = ARP_REQUEST;
    memcpy(info.sender_hw_address, hw_address, ETHER_ADDRLEN);
    info.target_ip_address = ip_address;

    return packet_new_with_info(&info, packet_len);
}

static ArpPacket *
packet_new_announcement (guint32 ip_address,
                         const guint8* hw_address,
                         size_t *packet_len)
{
    ArpPacketInfo info;

    memset(&info, 0, sizeof(info));
    info.operation = ARP_REQUEST;
    memcpy(info.sender_hw_address, hw_address, ETHER_ADDRLEN);
    info.target_ip_address = ip_address;
    info.sender_ip_address = ip_address;

    return packet_new_with_info(&info, packet_len);
}

static int
packet_parse (const ArpPacket *packet, size_t packet_len, ArpPacketInfo *info)
{
    const uint8_t *p;

    g_assert (packet);
    p = (guint8 *) packet->ether_payload;
    g_assert (p);

    if (packet_len < ARP_PACKET_SIZE)
        return -1;

    /* Check HTYPE and PTYPE */
    if (p[0] != 0 || p[1] != 1 || p[2] != 8 || p[3] != 0)
        return -1;

    /* Check HLEN, PLEN, OPERATION */
    if (p[4] != ETHER_ADDRLEN || p[5] != 4 || p[6] != 0 || (p[7] != 1 && p[7] != 2))
        return -1;

    info->operation = p[7];
    memcpy(info->sender_hw_address, p+8, ETHER_ADDRLEN);
    memcpy(&info->sender_ip_address, p+14, 4);
    memcpy(info->target_hw_address, p+18, ETHER_ADDRLEN);
    memcpy(&info->target_ip_address, p+24, 4);

    return 0;
}

/* Linux 'packet socket' specific implementation */

static int
send_packet (int fd, int ifindex, ArpPacket *packet, size_t packet_len)
{
    struct sockaddr_ll sa;

    g_assert (fd >= 0);
    g_assert (packet);
    g_assert (packet_len > 0);

    memset (&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons (ETH_P_ARP);
    sa.sll_ifindex = ifindex;
    sa.sll_halen = ETHER_ADDRLEN;
    memset (sa.sll_addr, 0xFF, ETHER_ADDRLEN);

    if (sendto (fd, packet->ether_payload, packet_len, 0, (struct sockaddr*) &sa, sizeof(sa)) < 0) {
        nm_log_err (LOGD_AUTOIP4, "sendto() failed: %s", strerror (errno));
        return -1;
    }

    return 0;
}

static ArpPacket *
recv_packet (int fd, ArpPacket **packet, size_t *packet_len)
{
	ArpPacket *packet;
    int s;
    struct sockaddr_ll sa;
    socklen_t sa_len;
    ssize_t r;

    g_assert (fd >= 0);
    g_assert (packet_len);

    if (ioctl (fd, FIONREAD, &s) < 0) {
        nm_log_err (LOGD_AUTOIP4, "FIONREAD failed: %s", strerror (errno));
		return NULL;
    }

    if (s <= 0)
        s = 4096;

    packet = packet_new (s);

    sa_len = sizeof (sa);
    if ((r = recvfrom (fd, packet->ether_payload, s, 0, (struct sockaddr*) &sa, &sa_len)) < 0) {
        nm_log_err (LOGD_AUTOIP4, "recvfrom() failed: %s", strerror (errno));
		g_free (packet);
		return NULL;
    }

    *packet_len = (size_t) r;
    return packet;
}

static void
set_state (NMIP4ll *self, State new_state, int reset_counter)
{
    static const char* const state_table[] = {
        [STATE_UNKNOWN] = "UNKNOWN",
        [STATE_WAITING_PROBE] = "WAITING_PROBE",
        [STATE_PROBING] = "PROBING",
        [STATE_WAITING_ANNOUNCE] = "WAITING_ANNOUNCE",
        [STATE_ANNOUNCING] = "ANNOUNCING",
        [STATE_RUNNING] = "RUNNING",
        [STATE_SLEEPING] = "SLEEPING"
    };

    g_assert (new_state < STATE_MAX);

    if (new_state == self->priv->state && !reset_counter) {
        self->priv->n_iteration++;
        nm_log_dbg (LOGD_AUTOIP4, "State iteration %s-%i",
                    state_table[new_state],
                    self->priv->n_iteration);
    } else {
        nm_log_dbg (LOGD_AUTOIP4, "State transition %s-%i -> %s-0",
                   state_table[self->priv->state],
                   self->priv->n_iteration,
                   state_table[new_state]);
        self->priv->state = new_state;
        self->priv->n_iteration = 0;
    }
}

static gboolean
channel_event_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMIP4ll *self = NM_IP4LL (user_data);
	GError *error = NULL;
	ArpPacketInfo info;
	int fd;
	int conflict = 0;
    ArpPacket *in_packet = NULL;


	fd = g_io_channel_unix_get_fd (source);
	if (recv_packet (fd, &in_packet, &in_packet_len) < 0)
		goto fail;

	if (packet_parse (in_packet, in_packet_len, &info) < 0) {
		nm_log_warn (LOGD_AUTOIP4, "Failed to parse incoming ARP packet.");
		goto done;
	}

	if (info.sender_ip_address == addr) {
	    if (memcmp (self->priv->hwaddr, info.sender_hw_address, ETHER_ADDRLEN)) {
	        /* Normal conflict */
	        conflict = 1;
	        nm_log_info (LOGD_AUTOIP4, "Received conflicting normal ARP packet.");
	    } else
	        nm_log_dbg (LOGD_AUTOIP4, "Received ARP packet back on source interface. Ignoring.");

	} else if (   self->priv->state == STATE_WAITING_PROBE
	           || self->priv->state == STATE_PROBING
	           || self->priv->state == STATE_WAITING_ANNOUNCE) {
	    /* Probe conflict */
	    conflict = (info.target_ip_address == addr) &&
	    	memcmp (self->priv->hwaddr, info.sender_hw_address, ETHER_ADDRLEN);

	    if (conflict)
	        nm_log_info (LOGD_AUTOIP4, "Received conflicting probe ARP packet.");
	}

	if (conflict) {
	    if (self->priv->state == STATE_RUNNING || self->priv->state == STATE_ANNOUNCING)
	        if (do_callout(dispatcher, CALLOUT_CONFLICT, iface, addr) < 0)
	            goto fail;

	    /* Pick a new address */
	    addr = pick_addr (addr);

	    nm_log_dbg (LOGD_AUTOIP4, "Trying address %s", inet_ntop(AF_INET, &addr, buf, sizeof(buf)));

	    self->priv->n_conflict++;

	    set_state (STATE_WAITING_PROBE, 1, addr);

	    if (self->priv->n_conflict >= MAX_CONFLICTS) {
	        nm_log_warn (LOGD_AUTOIP4, "Got too many conflicts, rate limiting new probes.");
	        schedule_timeout (self, RATE_LIMIT_INTERVAL * 1000, PROBE_WAIT * 1000);
	    } else
	        schedule_timeout (self, 0, PROBE_WAIT * 1000);

	} else {
	    nm_log_dbg (LOGD_AUTOIP4, "Ignoring irrelevant ARP packet.");
	}

	return TRUE;
}

static gboolean
timeout_cb (gpointer user_data)
{
	NMIP4ll *self = NM_IP4LL (user_data);

	self->priv->timeout_id = 0;

    if ((self->priv->state == STATE_WAITING_PROBE) ||
        (self->priv->state == STATE_PROBING && n_iteration < PROBE_NUM - 2)) {

        /* Send a probe */
        out_packet = packet_new_probe(addr, hw_address, &out_packet_len);
        set_state (STATE_PROBING, 0, addr);
		schedule_timeout (self, PROBE_MIN * 1000, (PROBE_MAX - PROBE_MIN) * 1000);

    } else if (self->priv->state == STATE_PROBING && n_iteration >= PROBE_NUM - 2) {

        /* Send the last probe */
        out_packet = packet_new_probe(addr, hw_address, &out_packet_len);
        set_state (STATE_WAITING_ANNOUNCE, 1, addr);
		schedule_timeout (self, ANNOUNCE_WAIT * 1000, 0);

    } else if ((self->priv->state == STATE_WAITING_ANNOUNCE) ||
               (self->priv->state == STATE_ANNOUNCING && n_iteration < ANNOUNCE_NUM-1)) {

        /* Send announcement packet */
        out_packet = packet_new_announcement (addr, self->priv->hwaddr, &out_packet_len);
        set_state (STATE_ANNOUNCING, 0, addr);
		schedule_timeout (self, ANNOUNCE_INTERVAL * 1000, 0);

        if (n_iteration == 0) {
            if (do_callout(dispatcher, CALLOUT_BIND, iface, addr) < 0)
                goto fail;
            n_conflict = 0;
        }

    } else if (self->priv->state == STATE_ANNOUNCING && n_iteration >= ANNOUNCE_NUM-1) {

        nm_log_dbg (LOGD_AUTOIP4, "Successfully claimed IP address %s",
                    inet_ntop (AF_INET, &addr, buf, sizeof(buf)));
        set_state (STATE_RUNNING, 0, addr);
	}

	if (out_packet) {
		nm_log_warn (LOGD_AUTOIP4, "sending...");
		if (send_packet (fd, ifindex, out_packet, out_packet_len) < 0)
		    goto fail;

		avahi_free (out_packet);
		out_packet = NULL;
	}

	return G_SOURCE_REMOVE;
}

static void
schedule_timeout (NMIP4ll *self, guint msec, guint jitter)
{
	GTimeVal tv = { 0, 0 };

    g_get_current_time (&tv);

    if (msec)
        g_time_val_add (&tv, (glong) msec*1000);

    if (jitter)
        g_time_val_add (&tv, (glong) (jitter * 1000.0 * rand () / (RAND_MAX + 1.0)));

	if (self->priv->timeout_id)
		g_source_remove (self->priv->timeout_id);
	self->priv->timeout_id = g_timeout_add ((tv.tv_sec * 1000) + (tv.tv_usec / 1000),
	                                        timeout_cb,
	                                        self);
}

gboolean
nm_ip4ll_start (NMIP4ll *self)
{
	int fd;
    struct sockaddr_ll sa;
    socklen_t sa_len;
    guint32 a = 0, addr = 0;
    guint i;

	g_return_val_if_fail (self->priv->ifindex > 0);
	g_return_val_if_fail (self->priv->hwaddr_len > 0);

    if ((fd = socket (PF_PACKET, SOCK_DGRAM, 0)) < 0) {
        nm_log_err (LOGD_AUTOIP4, "socket() failed: %s", strerror (errno));
		return FALSE;
    }

    memset (&sa, 0, sizeof (sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons (ETH_P_ARP);
    sa.sll_ifindex = self->priv->ifindex;

    if (bind (fd, (struct sockaddr*) &sa, sizeof (sa)) < 0) {
        nm_log_err (LOGD_AUTOIP4, "bind() failed: %s", strerror (errno));
        goto fail;
    }

    for (i = 0; i < self->priv->hwaddr_len; i++)
        a += self->priv->hwaddr[i] * i;
    a = (a % 0xFE00) + 0x0100;
    addr = htonl (IPV4LL_NETWORK | a);
    g_assert (is_ll_address (addr));

	self->priv->channel = g_io_channel_unix_new (fd);
	g_io_channel_set_encoding (self->priv->channel, NULL, NULL);
	g_io_channel_set_buffered (self->priv->channel, FALSE);
	self->priv->event_id = g_io_add_watch (self->priv->channel, G_IO_IN, channel_event_cb, self);

	/* First, wait a random time */
	set_state (STATE_WAITING_PROBE, 1, addr);
	schedule_timeout (self, 0, PROBE_WAIT * 1000);

	return TRUE;

fail:
	if (fd >= 0)
		close (fd);
	return FALSE;
}

/*****************************************************************/

NMIP4ll *
nm_ip4ll_new (int ifindex, guint8 *hwaddr, guint32 hwaddr_len)
{
	GByteArray *array;

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (hwaddr != NULL, NULL);
	g_return_val_if_fail (hwaddr_len <= NM_UTILS_HWADDR_LEN_MAX, NULL);

	array = g_byte_array_sized_new (hwaddr_len);
	g_byte_array_append (array, hwaddr, hwaddr_len);

	ll = (NMIP4ll *) g_object_new (NM_TYPE_IP4LL,
	                               NM_IP4LL_IFINDEX, ifindex,
	                               NM_IP4LL_HWADDR, array,
	                               NULL);
	g_byte_array_free (array, TRUE);
	return ll;
}

static void
nm_ip4ll_init (NMIP4ll *self)
{
	self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
	                                          NM_TYPE_IP4LL,
	                                          NMIP4llPrivate);
}

static void
dispose (GObject *object)
{
	G_OBJECT_CLASS (nm_ip4ll_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMIP4ll *self = NM_IP4LL (object);
	GByteArray *array;

	switch (prop_id) {
	case PROP_IFINDEX:
		g_return_if_fail (self->priv->ifindex == 0);
		self->priv->ifindex = g_value_get_int (value);
		g_warn_if_fail (self->priv->ifindex > 0);
		break;
	case PROP_HWADDR:
		array = g_value_get_boxed (value);
		g_return_if_fail (array->len <= NM_UTILS_HWADDR_LEN_MAX);
		memcpy (self->priv->hwaddr, array->data, array->len);
		self->priv->hwaddr_len = array->len;
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip4ll_class_init (NMIP4llClass *ll_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ll_class);

	g_type_class_add_private (config_class, sizeof (NMIP4llPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	/* properties */
	g_object_class_install_property (object_class, PROP_IFINDEX,
		 g_param_spec_int (NM_IP4LL_IFINDEX, "ifindex", "ifindex",
		                   0, G_MAXINT, 0,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_HWADDR,
		 g_param_spec_boxed (NM_IP4LL_HWADDR, "hwaddr", "hwaddr",
		                     G_TYPE_BYTE_ARRAY,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
