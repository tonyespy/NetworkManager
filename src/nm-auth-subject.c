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
 * Copyright (C) 2013 - 2014 Red Hat, Inc.
 */

/**
 * SECTION:nm-auth-subject
 * @short_description: Encapsulates authentication information about a requestor
 *
 * #NMAuthSubject encpasulates identifying information about an entity that
 * makes requests, like process identifier and user UID.
 */

#include "config.h"

#include "nm-auth-subject.h"

#include <string.h>
#include <stdlib.h>
#include <gio/gio.h>

#include "nm-dbus-manager.h"
#include "nm-enum-types.h"
#include "nm-glib-compat.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMAuthSubject, nm_auth_subject, G_TYPE_OBJECT)

#define NM_AUTH_SUBJECT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AUTH_SUBJECT, NMAuthSubjectPrivate))

enum {
	PROP_0,
	PROP_SUBJECT_TYPE,
	PROP_UNIX_PROCESS_DBUS_SENDER,
	PROP_UNIX_PROCESS_PID,
	PROP_UNIX_PROCESS_UID,

	PROP_LAST,
};

typedef struct {
	NMAuthSubjectType subject_type;
	struct {
		gulong pid;
		gulong uid;
		guint64 start_time;
		char *dbus_sender;
	} unix_process;
} NMAuthSubjectPrivate;

/**************************************************************/

#define CHECK_SUBJECT(self, error_value) \
	NMAuthSubjectPrivate *priv; \
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (self), error_value); \
	priv = NM_AUTH_SUBJECT_GET_PRIVATE (self); \

#define CHECK_SUBJECT_TYPED(self, expected_subject_type, error_value) \
	CHECK_SUBJECT (self, error_value); \
	g_return_val_if_fail (priv->subject_type == (expected_subject_type), error_value);

const char *
nm_auth_subject_to_string (NMAuthSubject *self, char *buf, gsize buf_len)
{
	CHECK_SUBJECT (self, NULL);

	switch (priv->subject_type) {
	case NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS:
		g_snprintf (buf, buf_len, "unix-process[pid=%lu, uid=%lu, start=%llu]",
		            (long unsigned) priv->unix_process.pid,
		            (long unsigned) priv->unix_process.uid,
		            (long long unsigned) priv->unix_process.start_time);
		break;
	case NM_AUTH_SUBJECT_TYPE_INTERNAL:
		g_strlcat (buf, "internal", buf_len);
		break;
	default:
		g_strlcat (buf, "invalid", buf_len);
		break;
	}
	return buf;
}

#if WITH_POLKIT

/* returns a floating variant */
GVariant *
nm_auth_subject_unix_process_to_polkit_gvariant (NMAuthSubject *self)
{
	GVariantBuilder builder;
	GVariant *dict;
	GVariant *ret;
	CHECK_SUBJECT_TYPED (self, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&builder, "{sv}", "pid",
	                       g_variant_new_uint32 (priv->unix_process.pid));
	g_variant_builder_add (&builder, "{sv}", "start-time",
	                       g_variant_new_uint64 (priv->unix_process.start_time));
	g_variant_builder_add (&builder, "{sv}", "uid",
	                       g_variant_new_int32 (priv->unix_process.uid));
	dict = g_variant_builder_end (&builder);
	ret = g_variant_new ("(s@a{sv})", "unix-process", dict);
	return ret;
}

#endif

NMAuthSubjectType
nm_auth_subject_get_subject_type (NMAuthSubject *subject)
{
	CHECK_SUBJECT (subject, NM_AUTH_SUBJECT_TYPE_INVALID);

	return priv->subject_type;
}

gboolean
nm_auth_subject_is_internal (NMAuthSubject *subject)
{
	return nm_auth_subject_get_subject_type (subject) == NM_AUTH_SUBJECT_TYPE_INTERNAL;
}

gboolean
nm_auth_subject_is_unix_process (NMAuthSubject *subject)
{
	return nm_auth_subject_get_subject_type (subject) == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
}

gulong
nm_auth_subject_get_unix_process_pid (NMAuthSubject *subject)
{
	CHECK_SUBJECT_TYPED (subject, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, G_MAXULONG);

	return priv->unix_process.pid;
}

gulong
nm_auth_subject_get_unix_process_uid (NMAuthSubject *subject)
{
	CHECK_SUBJECT_TYPED (subject, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, G_MAXULONG);

	return priv->unix_process.uid;
}

const char *
nm_auth_subject_get_unix_process_dbus_sender (NMAuthSubject *subject)
{
	CHECK_SUBJECT_TYPED (subject, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS, NULL);

	return priv->unix_process.dbus_sender;
}

/**************************************************************/

static NMAuthSubject *
_new_unix_process (DBusGMethodInvocation *context,
                   DBusConnection *connection,
                   DBusMessage *message)
{
	NMAuthSubject *self;
	gboolean success = FALSE;
	gulong pid = 0, uid = 0;
	char *dbus_sender = NULL;

	g_return_val_if_fail (context || (connection && message), NULL);

	if (context) {
		success = nm_dbus_manager_get_caller_info (nm_dbus_manager_get (),
		                                           context,
		                                           &dbus_sender,
		                                           &uid,
		                                           &pid);
	} else if (message) {
		success = nm_dbus_manager_get_caller_info_from_message (nm_dbus_manager_get (),
		                                                        connection,
		                                                        message,
		                                                        &dbus_sender,
		                                                        &uid,
		                                                        &pid);
	} else
		g_assert_not_reached ();

	if (!success)
		return NULL;

	g_return_val_if_fail (dbus_sender && *dbus_sender, NULL);
	/* polkit glib library stores uid and pid as gint. There might be some
	 * pitfalls if the id ever happens to be larger then that. Just assert against
	 * it here. */
	g_return_val_if_fail (uid <= MIN (G_MAXINT, G_MAXINT32), NULL);
	g_return_val_if_fail (pid > 0 && pid <= MIN (G_MAXINT, G_MAXINT32), NULL);

	self = NM_AUTH_SUBJECT (g_object_new (NM_TYPE_AUTH_SUBJECT,
	                                      NM_AUTH_SUBJECT_SUBJECT_TYPE, NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS,
	                                      NM_AUTH_SUBJECT_UNIX_PROCESS_DBUS_SENDER, dbus_sender,
	                                      NM_AUTH_SUBJECT_UNIX_PROCESS_PID, (gulong) pid,
	                                      NM_AUTH_SUBJECT_UNIX_PROCESS_UID, (gulong) uid,
	                                      NULL));

	if (NM_AUTH_SUBJECT_GET_PRIVATE (self)->subject_type != NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS) {
		/* this most likely happened because the process is gone (start_time==0).
		 * Either that is not assert-worthy, or constructed() already asserted.
		 * Just return NULL. */
		g_clear_object (&self);
	}
	return self;
}

NMAuthSubject *
nm_auth_subject_new_unix_process_from_context (DBusGMethodInvocation *context)
{
	return _new_unix_process (context, NULL, NULL);
}

NMAuthSubject *
nm_auth_subject_new_unix_process_from_message (DBusConnection *connection,
                                               DBusMessage *message)
{
	return _new_unix_process (NULL, connection, message);
}

/**
 * nm_auth_subject_new_internal():
 *
 * Creates a new auth subject representing the NetworkManager process itself.
 *
 * Returns: the new #NMAuthSubject
 */
NMAuthSubject *
nm_auth_subject_new_internal (void)
{
	return NM_AUTH_SUBJECT (g_object_new (NM_TYPE_AUTH_SUBJECT,
	                                      NM_AUTH_SUBJECT_SUBJECT_TYPE, NM_AUTH_SUBJECT_TYPE_INTERNAL,
	                                      NULL));
}

/**************************************************************/

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SUBJECT_TYPE:
		g_value_set_enum (value, priv->subject_type);
		break;
	case PROP_UNIX_PROCESS_DBUS_SENDER:
		g_value_set_string (value, priv->unix_process.dbus_sender);
		break;
	case PROP_UNIX_PROCESS_PID:
		g_value_set_ulong (value, priv->unix_process.pid);
		break;
	case PROP_UNIX_PROCESS_UID:
		g_value_set_ulong (value, priv->unix_process.uid);
		break;
	default:
		 G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		 break;
	}
}

static void
set_property (GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (object);
	NMAuthSubjectType subject_type;
	const char *str;
	gulong id;

	/* all properties are construct-only */
	switch (prop_id) {
	case PROP_SUBJECT_TYPE:
		subject_type = g_value_get_enum (value);
		g_return_if_fail (subject_type != NM_AUTH_SUBJECT_TYPE_INVALID);
		priv->subject_type |= subject_type;
		g_return_if_fail (priv->subject_type == subject_type);
		break;
	case PROP_UNIX_PROCESS_DBUS_SENDER:
		if ((str = g_value_get_string (value))) {
			priv->subject_type |= NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
			g_return_if_fail (priv->subject_type == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS);
			priv->unix_process.dbus_sender = g_strdup (str);
		}
		break;
	case PROP_UNIX_PROCESS_PID:
		if ((id = g_value_get_ulong (value)) != G_MAXULONG) {
			priv->subject_type |= NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
			g_return_if_fail (priv->subject_type == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS);
			priv->unix_process.pid = id;
		}
		break;
	case PROP_UNIX_PROCESS_UID:
		if ((id = g_value_get_ulong (value)) != G_MAXULONG) {
			priv->subject_type |= NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS;
			g_return_if_fail (priv->subject_type == NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS);
			priv->unix_process.uid = id;
		}
		break;
	default:
		 G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		 break;
	}
}

static void
_clear_private (NMAuthSubjectPrivate *priv)
{
	priv->subject_type = NM_AUTH_SUBJECT_TYPE_INVALID;
	priv->unix_process.pid = G_MAXULONG;
	priv->unix_process.uid = G_MAXULONG;
	g_clear_pointer (&priv->unix_process.dbus_sender, g_free);
}

static void
nm_auth_subject_init (NMAuthSubject *self)
{
	_clear_private (NM_AUTH_SUBJECT_GET_PRIVATE (self));
}

static void
constructed (GObject *object)
{
	NMAuthSubject *self = NM_AUTH_SUBJECT (object);
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (self);

	/* validate that the created instance. */

	switch (priv->subject_type) {
	case NM_AUTH_SUBJECT_TYPE_INTERNAL:
		priv->unix_process.pid = G_MAXULONG;
		priv->unix_process.uid = 0;  /* internal uses 'root' user */
		return;
	case NM_AUTH_SUBJECT_TYPE_UNIX_PROCESS:
		/* Ensure pid and uid to be representable as int32.
		 * DBUS treats them as uint32, polkit library as gint. */
		if (priv->unix_process.pid > MIN (G_MAXINT, G_MAXINT32))
			break;
		if (priv->unix_process.uid > MIN (G_MAXINT, G_MAXINT32)) {
			/* for uid==-1, libpolkit-gobject-1 detects the user based on the process id.
			 * Don't bother and require the user id as parameter. */
			break;
		}
		if (!priv->unix_process.dbus_sender || !*priv->unix_process.dbus_sender)
			break;

		priv->unix_process.start_time = nm_utils_get_start_time_for_pid (priv->unix_process.pid);

		if (!priv->unix_process.start_time) {
			/* could not detect the process start time. The subject is invalid, but don't
			 * assert against it. */
			_clear_private (priv);
		}
		return;
	default:
		break;
	}

	_clear_private (priv);
	g_return_if_reached ();
}

static void
finalize (GObject *object)
{
	NMAuthSubjectPrivate *priv = NM_AUTH_SUBJECT_GET_PRIVATE (object);

	_clear_private (priv);

	G_OBJECT_CLASS (nm_auth_subject_parent_class)->finalize (object);
}

static void
nm_auth_subject_class_init (NMAuthSubjectClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMAuthSubjectPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->finalize = finalize;

	g_object_class_install_property
	    (object_class, PROP_SUBJECT_TYPE,
	     g_param_spec_enum (NM_AUTH_SUBJECT_SUBJECT_TYPE, "", "",
	                        NM_TYPE_AUTH_SUBJECT_TYPE,
	                        NM_AUTH_SUBJECT_TYPE_INVALID,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT_ONLY |
	                        G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_UNIX_PROCESS_DBUS_SENDER,
	     g_param_spec_string (NM_AUTH_SUBJECT_UNIX_PROCESS_DBUS_SENDER, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	     (object_class, PROP_UNIX_PROCESS_PID,
	      g_param_spec_ulong (NM_AUTH_SUBJECT_UNIX_PROCESS_PID, "", "",
	                          0, G_MAXULONG, G_MAXULONG,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	     (object_class, PROP_UNIX_PROCESS_UID,
	      g_param_spec_ulong (NM_AUTH_SUBJECT_UNIX_PROCESS_UID, "", "",
	                          0, G_MAXULONG, G_MAXULONG,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS));

}
