/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Thomas Graf <tgraf@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2011 - 2013 Red Hat, Inc.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dbus/dbus-glib.h>
#include <glib/gi18n.h>

#include "nm-setting-bond.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-bond
 * @short_description: Describes connection properties for bonds
 * @include: nm-setting-bond.h
 *
 * The #NMSettingBond object is a #NMSetting subclass that describes properties
 * necessary for bond connections.
 **/

/**
 * nm_setting_bond_error_quark:
 *
 * Registers an error quark for #NMSettingBond if necessary.
 *
 * Returns: the error quark used for #NMSettingBond errors.
 **/
GQuark
nm_setting_bond_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-bond-error-quark");
	return quark;
}


G_DEFINE_TYPE_WITH_CODE (NMSettingBond, nm_setting_bond, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_BOND_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_BOND_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_BOND)

#define NM_SETTING_BOND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BOND, NMSettingBondPrivate))

typedef struct {
	char *interface_name;
	char *mode;
	guint miimon;
	guint downdelay;
	guint updelay;
	guint arp_interval;
	char **arp_ip_target;
	char *arp_validate;
	char *primary;
	char *primary_reselect;
	char *fail_over_mac;
	char *ad_select;
	char *xmit_hash_policy;
	gboolean use_carrier;
	guint resend_igmp;

	GHashTable *options;
} NMSettingBondPrivate;

enum {
	PROP_0,
	PROP_INTERFACE_NAME,

	PROP_MODE,
	PROP_MIIMON,
	PROP_DOWNDELAY,
	PROP_UPDELAY,
	PROP_ARP_INTERVAL,
	PROP_ARP_IP_TARGET,
	PROP_ARP_VALIDATE,
	PROP_PRIMARY,
	PROP_PRIMARY_RESELECT,
	PROP_FAIL_OVER_MAC,
	PROP_USE_CARRIER,
	PROP_AD_SELECT,
	PROP_XMIT_HASH_POLICY,
	PROP_RESEND_IGMP,

	PROP_OPTIONS,
	LAST_PROP
};
#define _FIRST_LEGACY_PROP PROP_MODE
#define _LAST_LEGACY_PROP PROP_RESEND_IGMP

enum {
	TYPE_INT,
	TYPE_STR,
	TYPE_BOTH,
	TYPE_IP,
	TYPE_IFNAME,
};

typedef struct {
	guint opt_type;
	const char *legacy_name;
	const char *list[10];
	GParamSpec *pspec;
	char *defval;
} BondProperty;

static BondProperty props[ LAST_PROP + 1 ] = {
	[PROP_MODE]             = { TYPE_BOTH,   NM_SETTING_BOND_OPTION_MODE,
	                            { "balance-rr", "active-backup", "balance-xor", "broadcast", "802.3ad", "balance-tlb", "balance-alb" } },
	[PROP_MIIMON]           = { TYPE_INT,    NM_SETTING_BOND_OPTION_MIIMON },
	[PROP_DOWNDELAY]        = { TYPE_INT,    NM_SETTING_BOND_OPTION_DOWNDELAY },
	[PROP_UPDELAY]          = { TYPE_INT,    NM_SETTING_BOND_OPTION_UPDELAY },
	[PROP_ARP_INTERVAL]     = { TYPE_INT,    NM_SETTING_BOND_OPTION_ARP_INTERVAL },
	[PROP_ARP_IP_TARGET]    = { TYPE_IP,     NM_SETTING_BOND_OPTION_ARP_IP_TARGET },
	[PROP_ARP_VALIDATE]     = { TYPE_BOTH,   NULL,
	                            { "none", "active", "backup", "all" } },
	[PROP_PRIMARY]          = { TYPE_IFNAME, NULL },
	[PROP_PRIMARY_RESELECT] = { TYPE_BOTH,   NULL,
	                            { "always", "better", "failure" } },
	[PROP_FAIL_OVER_MAC]    = { TYPE_BOTH,   NULL,
	                            { "none", "active", "follow" } },
	[PROP_USE_CARRIER]      = { TYPE_INT },
	[PROP_AD_SELECT]        = { TYPE_BOTH,   NULL,
	                          { "stable", "bandwidth", "count" } },
	[PROP_XMIT_HASH_POLICY] = { TYPE_STR,    NULL,
	                          { "layer2", "layer2+3", "layer3+4", "encap2+3", "encap3+4" } },
	[PROP_RESEND_IGMP]      = { TYPE_INT },
};

/**
 * nm_setting_bond_new:
 *
 * Creates a new #NMSettingBond object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBond object
 **/
NMSetting *
nm_setting_bond_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_BOND, NULL);
}

/*****************************************************************************/

/**
 * nm_setting_bond_get_interface_name:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:interface-name property of the setting
 **/
const char *
nm_setting_bond_get_interface_name (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->interface_name;
}

/**
 * nm_setting_bond_get_mode:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:mode property of the setting
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_bond_get_mode (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->mode;
}

/**
 * nm_setting_bond_get_miimon:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:miimon property of the setting
 *
 * Since: 0.9.10
 **/
guint
nm_setting_bond_get_miimon (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->miimon;
}

/**
 * nm_setting_bond_get_downdelay:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:downdelay property of the setting
 *
 * Since: 0.9.10
 **/
guint
nm_setting_bond_get_downdelay (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->downdelay;
}

/**
 * nm_setting_bond_get_updelay:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:updelay property of the setting
 *
 * Since: 0.9.10
 **/
guint
nm_setting_bond_get_updelay (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->updelay;
}

/**
 * nm_setting_bond_get_arp_interval:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:arp-interval property of the setting
 *
 * Since: 0.9.10
 **/
guint
nm_setting_bond_get_arp_interval (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->arp_interval;
}

/**
 * nm_setting_bond_get_arp_ip_target:
 * @setting: the #NMSettingBond
 *
 * Returns: (transfer none): the #NMSettingBond:arp-ip-target property
 *   of the setting (which belongs to the setting and must not be freed).
 *
 * Since: 0.9.10
 **/
const char *const*
nm_setting_bond_get_arp_ip_target (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return (const char *const*) NM_SETTING_BOND_GET_PRIVATE (setting)->arp_ip_target;
}

/**
 * nm_setting_bond_get_arp_validate:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:arp-validate property of the setting
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_bond_get_arp_validate (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->arp_validate;
}

/**
 * nm_setting_bond_get_primary:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:primary property of the setting
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_bond_get_primary (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->primary;
}

/**
 * nm_setting_bond_get_primary_reselect:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:primary-reselect property of the setting
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_bond_get_primary_reselect (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->primary_reselect;
}

/**
 * nm_setting_bond_get_fail_over_mac:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:fail-over-mac property of the setting
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_bond_get_fail_over_mac (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->fail_over_mac;
}

/**
 * nm_setting_bond_get_use_carrier:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:use-carrier property of the setting
 *
 * Since: 0.9.10
 **/
gboolean
nm_setting_bond_get_use_carrier (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), FALSE);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->use_carrier;
}

/**
 * nm_setting_bond_get_ad_select:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:ad-select property of the setting
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_bond_get_ad_select (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->ad_select;
}

/**
 * nm_setting_bond_get_xmit_hash_policy:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:xmit-hash-policy property of the setting
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_bond_get_xmit_hash_policy (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->xmit_hash_policy;
}

/**
 * nm_setting_bond_get_resend_igmp:
 * @setting: the #NMSettingBond
 *
 * Returns: the #NMSettingBond:resend-igmp property of the setting
 *
 * Since: 0.9.10
 **/
guint
nm_setting_bond_get_resend_igmp (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return NM_SETTING_BOND_GET_PRIVATE (setting)->resend_igmp;
}

/*****************************************************************************/

static BondProperty *
find_property (const char *name, const char **out_new_name, guint *out_idx)
{
	guint i;

	g_return_val_if_fail (name != NULL, NULL);

	for (i = _FIRST_LEGACY_PROP; i <= _LAST_LEGACY_PROP; i++) {
		const char *new_name = g_param_spec_get_name (props[i].pspec);

		if (strcmp (name, new_name) == 0 || g_strcmp0 (name, props[i].legacy_name) == 0) {
			if (out_new_name)
				*out_new_name = new_name;
			if (out_idx)
				*out_idx = i;
			return &props[i];
		}
	}
	return NULL;
}

/* For a new property or legacy option name, returns the new property name */
static const char *
get_property_name (const char *name, const BondProperty **out_prop)
{
	const char *new_name = NULL;

	*out_prop = find_property (name, &new_name, NULL);
	return *out_prop ? new_name : NULL;
}

/* For a new property or legacy option name, returns the legacy option name */
static const char *
get_legacy_name (GParamSpec *pspec)
{
	const BondProperty *prop;
	const char *new_name = NULL;

	prop = find_property (g_param_spec_get_name (pspec), &new_name, NULL);
	if (prop)
		return prop->legacy_name ? prop->legacy_name : new_name;

	return NULL;
}

/**
 * nm_setting_bond_get_num_options:
 * @setting: the #NMSettingBond
 *
 * Returns the number of options that are set in the legacy
 * #NMSettingBond:options property. This does not include other bond
 * properties which are not included in #NMSettingBond:options.
 *
 * Returns: the number of legacy bonding options
 *
 * Deprecated: use the option-specific getters instead.
 **/
guint32
nm_setting_bond_get_num_options (NMSettingBond *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), 0);

	return _LAST_LEGACY_PROP - _FIRST_LEGACY_PROP;
}

/**
 * nm_setting_bond_get_option:
 * @setting: the #NMSettingBond
 * @idx: index of the desired option, from 0 to
 * nm_setting_bond_get_num_options() - 1
 * @out_name: (out): on return, the name of the bonding option; this
 * value is owned by the setting and should not be modified
 * @out_value: (out): on return, the value of the name of the bonding
 * option; this value is owned by the setting and should not be modified
 *
 * Given an index, return the value of the bonding option at that index.  Indexes
 * are *not* guaranteed to be static across modifications to options done by
 * nm_setting_bond_add_option() and nm_setting_bond_remove_option(),
 * and should not be used to refer to options except for short periods of time
 * such as during option iteration.
 *
 * Returns: %TRUE on success if the index was valid and an option was found,
 * %FALSE if the index was invalid (ie, greater than the number of options
 * currently held by the setting)
 *
 * Deprecated: use the option-specific getters instead.
 **/
gboolean
nm_setting_bond_get_option (NMSettingBond *setting,
                            guint32 idx,
                            const char **out_name,
                            const char **out_value)
{
	NMSettingBondPrivate *priv;
	const char *legacy_name, *value;

	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), FALSE);
	priv = NM_SETTING_BOND_GET_PRIVATE (setting);

	idx += _FIRST_LEGACY_PROP;
	g_return_val_if_fail (idx <= _LAST_LEGACY_PROP, FALSE);

	legacy_name = get_legacy_name (props[idx].pspec);
	g_assert (legacy_name);
	value = g_hash_table_lookup (priv->options, legacy_name);
	if (!value)
		return FALSE;

	if (out_name)
		*out_name = legacy_name;
	if (out_value)
		*out_value = value;
	return TRUE;
}

static gboolean
int_from_string (const char *s, glong *out_num)
{
	guint i;

	for (i = 0; i < strlen (s); i++) {
		if (!g_ascii_isdigit (s[i]) && s[i] != '-')
			return FALSE;
	}

	errno = 0;
	*out_num = strtol (s, NULL, 10);
	return errno ? FALSE : TRUE;
}

static gboolean
validate_int (const BondProperty *prop, const char *value)
{
	GParamSpecInt *ispec;
	glong num = 0;

	if (!G_IS_PARAM_SPEC_INT (prop->pspec))
		return FALSE;
	if (!value)
		return FALSE;
	if (!int_from_string (value, &num))
		return FALSE;

	ispec = G_PARAM_SPEC_INT (prop->pspec);
	return (num >= ispec->minimum && num <= ispec->maximum);
}

static gboolean
validate_list (const BondProperty *prop, const char *value)
{
	guint i;

	if (!value)
		return FALSE;

	for (i = 0; i < G_N_ELEMENTS (prop->list) && prop->list[i]; i++) {
		if (g_strcmp0 (prop->list[i], value) == 0)
			return TRUE;
	}

	/* empty validation list means all values pass */
	return prop->list[0] == NULL ? TRUE : FALSE;
}

static gboolean
validate_both (const BondProperty *prop, const char *value)
{
	glong num = -1;

	g_assert (prop->list);

	if (!value)
		return FALSE;

	if (validate_list (prop, value))
		return TRUE;

	if (!int_from_string (value, &num))
		return FALSE;

	/* Ensure number is within bounds of string list */
	return num >= 0 && num < G_N_ELEMENTS (prop->list);
}

static char **
parse_ip (const char *value, gboolean warn_on_error)
{
	char **ips, **iter;
	struct in_addr addr;

	if (!value || !value[0]) {
		/* missing value is valid, we just NULL instead of an empty array. */
		return NULL;
	}

	ips = g_strsplit_set (value, ",", 0);
	for (iter = ips; *iter; iter++) {
		if (!inet_aton (*iter, &addr)) {
			g_strfreev (ips);
			g_return_val_if_fail (!warn_on_error, NULL);
			return NULL;
		}
	}
	return ips;
}

static gboolean
validate_ip (const char *value)
{
	char **ips;

	if (!value || !value[0]) {
		/* there is only one TYPE_IP, and that property is not mandatory.
		 * Accept empty as valid.
		 **/
		return TRUE;
	}

	/* make reuse of parse_ip, as it should validate the input anyway. */
	ips = parse_ip (value, FALSE);
	if (!ips)
		return FALSE;

	g_strfreev (ips);
	return TRUE;
}

static gboolean
validate_ifname (const char *value)
{
	if (!value || !value[0]) {
		/* there is only one TYPE_IFNAME, and that property is not mandatory.
		 * Accept empty as valid.
		 **/
		return TRUE;
	}

	return nm_utils_iface_valid_name (value);
}

/* Checks whether @value is is a valid value for @prop.
 *
 * Returns: TRUE, if the @value is valid for the given name.
 * If @value is NULL, false will be returned.
 **/
static gboolean
validate_property (const BondProperty *prop, const char *value)
{
	switch (prop->opt_type) {
	case TYPE_INT:
		return validate_int (prop, value);
	case TYPE_STR:
		return validate_list (prop, value);
	case TYPE_BOTH:
		return validate_both (prop, value);
	case TYPE_IP:
		return validate_ip (value);
	case TYPE_IFNAME:
		return validate_ifname (value);
	default:
		g_assert_not_reached();
	}
	return FALSE;
}

/**
 * nm_setting_bond_get_option_by_name:
 * @setting: the #NMSettingBond
 * @name: the option name for which to retrieve the value
 *
 * Returns the value associated with the bonding option specified by
 * @name, if it exists.
 *
 * Returns: the value, or %NULL if the key/value pair was never added to the
 * setting; the value is owned by the setting and must not be modified
 *
 * Deprecated: use the option-specific getters instead.
 **/
const char *
nm_setting_bond_get_option_by_name (NMSettingBond *setting,
                                    const char *name)
{
	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	return g_hash_table_lookup (NM_SETTING_BOND_GET_PRIVATE (setting)->options, name);
}

/**
 * nm_setting_bond_add_option:
 * @setting: the #NMSettingBond
 * @name: name for the option
 * @value: value for the option
 *
 * Add an option to the table.  The option is compared to an internal list
 * of allowed options.  Option names may contain only alphanumeric characters
 * (ie [a-zA-Z0-9]).  Adding a new name replaces any existing name/value pair
 * that may already exist.
 *
 * The order of how to set several options is relevant because there are options
 * that conflict with each other.
 *
 * Returns: %TRUE if the option was valid and was added to the internal option
 * list, %FALSE if it was not.
 *
 * Deprecated: use the option-specific properties instead.
 **/
gboolean
nm_setting_bond_add_option (NMSettingBond *setting,
                            const char *name,
                            const char *value)
{
	NMSettingBondPrivate *priv;
	GObject *object = G_OBJECT (setting);
	const BondProperty *prop = NULL;
	const char *prop_name;
	glong num = 0;

	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), FALSE);

	priv = NM_SETTING_BOND_GET_PRIVATE (setting);

	prop_name = get_property_name (name, &prop);
	if (!prop_name)
		return FALSE;
	if (!validate_property (prop, value))
		return FALSE;

	g_object_freeze_notify (object);

	switch (prop->opt_type) {
	case TYPE_INT:
		if (!int_from_string (value, &num))
			return FALSE;
		g_object_set (object, prop_name, (gint) num, NULL);
		break;
	case TYPE_BOTH: {
		const char *str_value = value;

		/* Might be an integer-as-string; find the string */
		if (!validate_list (prop, value)) {
			if (!int_from_string (value, &num))
				return FALSE;
			/* Be paranoid although it's already been checked by validate_property() */
			g_assert (num >= 0 && num < G_N_ELEMENTS (prop->list));
			str_value = prop->list[num];
		}
		g_object_set (object, prop_name, str_value, NULL);
		break;
	}
	case TYPE_IFNAME:
	case TYPE_STR:
		g_object_set (object, prop_name, value, NULL);
		break;
	case TYPE_IP: {
		char **ip = parse_ip (value, TRUE);

		g_object_set (object, prop_name, ip, NULL);
		g_strfreev (ip);
		break;
	}
	default:
		g_assert_not_reached ();
		break;
	}

	g_object_thaw_notify (object);

	return TRUE;
}

/**
 * nm_setting_bond_remove_option:
 * @setting: the #NMSettingBond
 * @name: name of the option to remove
 *
 * Remove the bonding option referenced by @name from the internal option
 * list.
 *
 * Returns: %TRUE if the option was found and removed from the internal option
 * list, %FALSE if it was not.
 *
 * Deprecated: use the option-specific properties instead.
 **/
gboolean
nm_setting_bond_remove_option (NMSettingBond *setting,
                               const char *name)
{
	GObject *object = G_OBJECT (setting);
	NMSettingBondPrivate *priv;
	const BondProperty *prop;
	const char *prop_name;
	GValue defval = G_VALUE_INIT;

	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), FALSE);
	priv = NM_SETTING_BOND_GET_PRIVATE (setting);

	prop_name = get_property_name (name, &prop);
	if (!prop_name)
		return FALSE;

	g_object_freeze_notify (object);

	/* we don't really remove the property, instead we reset the default value. */
	g_value_init (&defval, prop->pspec->value_type);
	g_param_value_set_default (prop->pspec, &defval);
	g_object_set_property (object, prop_name, &defval);
	g_value_unset (&defval);

	g_object_thaw_notify (object);
	return TRUE;
}

/**
 * nm_setting_bond_get_valid_options:
 * @setting: the #NMSettingBond
 *
 * Returns a list of valid bond options.
 *
 * Returns: (transfer none): a %NULL-terminated array of strings of valid bond options.
 *
 * Deprecated: the valid options are defined by the #NMSettingBond
 * properties.
 **/
const char **
nm_setting_bond_get_valid_options  (NMSettingBond *setting)
{
	static const char *array[LAST_PROP + 1] = { NULL };

	/* initialize the array once */
	if (G_UNLIKELY (array[0] == NULL)) {
		guint prop, i;

		for (prop = _FIRST_LEGACY_PROP, i = 0; prop <= _LAST_LEGACY_PROP; prop++, i++) {
			array[i] = props[prop].legacy_name ?
			      props[prop].legacy_name : g_param_spec_get_name (props[prop].pspec);
		}
	}

	return array;
}

/**
 * nm_setting_bond_get_option_default:
 * @setting: the #NMSettingBond
 * @name: the name of the option
 *
 * Returns: the value of the bond option if not overridden by an entry in
 *   the #NMSettingBond:options property.
 *
 * Deprecated: Use the default values of the option-specific properties.
 **/
const char *
nm_setting_bond_get_option_default (NMSettingBond *setting, const char *name)
{
	BondProperty *prop;
	GValue defval = G_VALUE_INIT;
	guint idx = 0;

	g_return_val_if_fail (NM_IS_SETTING_BOND (setting), NULL);

	prop = find_property (name, NULL, &idx);
	if (!prop)
		return NULL;

	if (G_UNLIKELY (prop->defval == NULL)) {
		if (idx == PROP_ARP_IP_TARGET)
			prop->defval = "";
		else {
			g_value_init (&defval, prop->pspec->value_type);
			g_param_value_set_default (prop->pspec, &defval);
			prop->defval = g_strdup_value_contents (&defval);
			g_value_unset (&defval);
		}
	}
	return prop->defval;
}

/*****************************************************************/

static void
set_properties_from_hash (NMSettingBond *self, GHashTable *options)
{
	const char *value;
	guint i;

	g_object_freeze_notify (G_OBJECT (self));

	/* Set each property to the value given by @options, or if not present
	 * in @options, to the default value.
	 */
	for (i = _FIRST_LEGACY_PROP; i <= _LAST_LEGACY_PROP; i++) {
		const char *new_name = g_param_spec_get_name (props[i].pspec);
		const char *legacy_name = new_name;
		GValue defval = G_VALUE_INIT;

		value = g_hash_table_lookup (options, legacy_name);
		if (!value)
			legacy_name = props[i].legacy_name;
		value = g_hash_table_lookup (options, legacy_name);

		if (value)
			nm_setting_bond_add_option (self, legacy_name, value);
		else {
			g_value_init (&defval, props[i].pspec->value_type);
			g_param_value_set_default (props[i].pspec, &defval);
			g_object_set_property (G_OBJECT (self), new_name, &defval);
			g_value_unset (&defval);
		}
	}

	g_object_thaw_notify (G_OBJECT (self));
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (setting);

	if (!priv->interface_name || !strlen (priv->interface_name)) {
		g_set_error_literal (error,
		                     NM_SETTING_BOND_ERROR,
		                     NM_SETTING_BOND_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_INTERFACE_NAME);
		return FALSE;
	}
	if (!nm_utils_iface_valid_name (priv->interface_name)) {
		g_set_error_literal (error,
		                     NM_SETTING_BOND_ERROR,
		                     NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_INTERFACE_NAME);
		return FALSE;
	}

	/* Can only set one of miimon and arp_interval */
	if (priv->miimon > 0 && priv->arp_interval > 0) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             _("only one of '%s' and '%s' can be set"),
		             NM_SETTING_BOND_OPTION_MIIMON,
		             NM_SETTING_BOND_OPTION_ARP_INTERVAL);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME,
		                priv->arp_ip_target == NULL && priv->arp_ip_target[0] ? NM_SETTING_BOND_ARP_INTERVAL : NM_SETTING_BOND_MIIMON);
	}

	if (!priv->mode) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_MISSING_PROPERTY,
		             _("mandatory property '%s' is missing"),
		             NM_SETTING_BOND_MODE);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_MODE);
		return FALSE;
	}
	if (!validate_property (&props[PROP_MODE], priv->mode)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for '%s'"),
		             priv->mode, NM_SETTING_BOND_MODE);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_MODE);
		return FALSE;
	}

	/* Make sure mode is compatible with other settings */
	if (   strcmp (priv->mode, "balance-alb") == 0
	    || strcmp (priv->mode, "balance-tlb") == 0) {
		if (priv->arp_interval > 0) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s=%s' is incompatible with '%s > 0'"),
			             NM_SETTING_BOND_OPTION_MODE, priv->mode,
			             NM_SETTING_BOND_OPTION_ARP_INTERVAL);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_ARP_INTERVAL);
			return FALSE;
		}
	}

	if (strcmp (priv->mode, "active-backup") == 0) {
		if (priv->primary && !nm_utils_iface_valid_name (priv->primary)) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid interface name"),
			             priv->primary);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_PRIMARY);
			return FALSE;
		}
	} else {
		if (priv->primary) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s' is only valid for '%s=%s'"),
			             NM_SETTING_BOND_PRIMARY,
			             NM_SETTING_BOND_MODE, "active-backup");
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_PRIMARY);
			return FALSE;
		}
	}

	if (nm_setting_find_in_list (all_settings, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		if (strcmp (priv->mode, "active-backup") != 0) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s=%s' is not a valid configuration for '%s'"),
			             NM_SETTING_BOND_OPTION_MODE, priv->mode,
			             NM_SETTING_INFINIBAND_SETTING_NAME);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_MODE);
			return FALSE;
		}
	}

	if (priv->miimon == 0) {
		/* updelay and downdelay can only be used with miimon */
		if (priv->updelay > 0) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s' property requires '%s' property to be set"),
			             NM_SETTING_BOND_UPDELAY, NM_SETTING_BOND_MIIMON);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_UPDELAY);
			return FALSE;
		}
		if (priv->downdelay > 0) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s' property requires '%s' property to be set"),
			             NM_SETTING_BOND_DOWNDELAY, NM_SETTING_BOND_MIIMON);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_DOWNDELAY);
			return FALSE;
		}
	}

	/* arp_ip_target can only be used with arp_interval, and must
	 * contain IPv4 addresses.
	 */
	if (priv->arp_interval > 0) {
		guint32 addr;
		int i;

		if (!priv->arp_ip_target) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_MISSING_PROPERTY,
			             _("'%s' property requires '%s' property to be set"),
			             NM_SETTING_BOND_ARP_INTERVAL, NM_SETTING_BOND_ARP_IP_TARGET);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_ARP_IP_TARGET);
			return FALSE;
		}

		if (!priv->arp_ip_target[0]) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s' property is empty"),
			             NM_SETTING_BOND_ARP_IP_TARGET);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_ARP_IP_TARGET);
			return FALSE;
		}

		for (i = 0; priv->arp_ip_target[i]; i++) {
			if (!inet_pton (AF_INET, priv->arp_ip_target[i], &addr)) {
				g_set_error (error,
				             NM_SETTING_BOND_ERROR,
				             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
				             _("'%s' is not a valid IPv4 address for '%s' property"),
				             priv->arp_ip_target[i], NM_SETTING_BOND_ARP_IP_TARGET);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_ARP_IP_TARGET);
				return FALSE;
			}
		}
	} else {
		if (priv->arp_ip_target && priv->arp_ip_target[0]) {
			g_set_error (error,
			             NM_SETTING_BOND_ERROR,
			             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
			             _("'%s' property requires '%s' property to be set"),
			             NM_SETTING_BOND_ARP_IP_TARGET, NM_SETTING_BOND_ARP_INTERVAL);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_ARP_IP_TARGET);
			return FALSE;
		}
	}

	/* FIXME: maybe we should not be too excessively about validating the strings,
	 * because the kernel might add new values (which we would then not support).
	 * OTOH, the checking above already requires some deep knowledge about the exact
	 * meaning of the flags, so, why check there, but not here?
	 **/
	if (priv->arp_validate && !validate_property (&props[PROP_ARP_VALIDATE], priv->arp_validate)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for '%s'"),
		             priv->arp_validate, NM_SETTING_BOND_ARP_VALIDATE);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_ARP_VALIDATE);
		return FALSE;
	}

	if (priv->primary_reselect && !validate_property (&props[PROP_PRIMARY_RESELECT], priv->primary_reselect)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for '%s'"),
		             priv->primary_reselect, NM_SETTING_BOND_PRIMARY_RESELECT);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_PRIMARY_RESELECT);
		return FALSE;
	}

	if (priv->fail_over_mac && !validate_property (&props[PROP_FAIL_OVER_MAC], priv->fail_over_mac)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for '%s'"),
		             priv->fail_over_mac, NM_SETTING_BOND_FAIL_OVER_MAC);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_FAIL_OVER_MAC);
		return FALSE;
	}

	if (priv->ad_select && !validate_property (&props[PROP_FAIL_OVER_MAC], priv->ad_select)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for '%s'"),
		             priv->ad_select, NM_SETTING_BOND_AD_SELECT);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_AD_SELECT);
		return FALSE;
	}

	if (priv->xmit_hash_policy && !validate_property (&props[PROP_FAIL_OVER_MAC], priv->xmit_hash_policy)) {
		g_set_error (error,
		             NM_SETTING_BOND_ERROR,
		             NM_SETTING_BOND_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for '%s'"),
		             priv->xmit_hash_policy, NM_SETTING_BOND_XMIT_HASH_POLICY);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BOND_SETTING_NAME, NM_SETTING_BOND_XMIT_HASH_POLICY);
		return FALSE;
	}

	return TRUE;
}

static const char *
get_virtual_iface_name (NMSetting *setting)
{
	NMSettingBond *self = NM_SETTING_BOND (setting);

	return nm_setting_bond_get_interface_name (self);
}

static void
nm_setting_bond_init (NMSettingBond *setting)
{
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (setting);

	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_BOND_SETTING_NAME, NULL);

	priv->options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static void
finalize (GObject *object)
{
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (object);

	g_free (priv->interface_name);
	g_free (priv->mode);
	g_free (priv->primary);
	g_strfreev (priv->arp_ip_target);
	g_hash_table_destroy (priv->options);

	G_OBJECT_CLASS (nm_setting_bond_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingBond *setting = NM_SETTING_BOND (object);
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (object);
	const char *legacy_name = get_legacy_name (pspec);
	char *legacy_value = NULL;

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		g_free (priv->interface_name);
		priv->interface_name = g_value_dup_string (value);
		break;
	case PROP_MODE:
		g_free (priv->mode);
		priv->mode = g_value_dup_string (value);
		legacy_value = g_value_dup_string (value);
		break;
	case PROP_MIIMON:
		priv->miimon = g_value_get_int (value);
		legacy_value = g_strdup_printf ("%u", g_value_get_int (value));
		break;
	case PROP_DOWNDELAY:
		priv->downdelay = g_value_get_int (value);
		legacy_value = g_strdup_printf ("%u", g_value_get_int (value));
		break;
	case PROP_UPDELAY:
		priv->updelay = g_value_get_int (value);
		legacy_value = g_strdup_printf ("%u", g_value_get_int (value));
		break;
	case PROP_ARP_INTERVAL:
		priv->arp_interval = g_value_get_int (value);
		legacy_value = g_strdup_printf ("%u", g_value_get_int (value));
		break;
	case PROP_ARP_IP_TARGET:
		g_strfreev (priv->arp_ip_target);
		priv->arp_ip_target = g_value_dup_boxed (value);
		legacy_value = priv->arp_ip_target ? g_strjoinv (",", priv->arp_ip_target) : g_strdup ("");
		break;
	case PROP_ARP_VALIDATE:
		g_free (priv->arp_validate);
		priv->arp_validate = g_value_dup_string (value);
		legacy_value = g_value_dup_string (value);
		break;
	case PROP_PRIMARY:
		g_free (priv->primary);
		priv->primary = g_value_dup_string (value);
		legacy_value = g_value_dup_string (value);
		break;
	case PROP_PRIMARY_RESELECT:
		g_free (priv->primary_reselect);
		priv->primary_reselect = g_value_dup_string (value);
		legacy_value = g_value_dup_string (value);
		break;
	case PROP_FAIL_OVER_MAC:
		g_free (priv->fail_over_mac);
		priv->fail_over_mac = g_value_dup_string (value);
		legacy_value = g_value_dup_string (value);
		break;
	case PROP_USE_CARRIER:
		priv->use_carrier = g_value_get_int (value);
		legacy_value = g_strdup_printf ("%u", g_value_get_int (value));
		break;
	case PROP_AD_SELECT:
		g_free (priv->ad_select);
		priv->ad_select = g_value_dup_string (value);
		legacy_value = g_value_dup_string (value);
		break;
	case PROP_XMIT_HASH_POLICY:
		g_free (priv->xmit_hash_policy);
		priv->xmit_hash_policy = g_value_dup_string (value);
		legacy_value = g_value_dup_string (value);
		break;
	case PROP_RESEND_IGMP:
		priv->resend_igmp = g_value_get_int (value);
		legacy_value = g_strdup_printf ("%u", g_value_get_int (value));
		break;
	case PROP_OPTIONS:
		set_properties_from_hash (setting, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}

	if (legacy_value) {
		g_hash_table_insert (priv->options, g_strdup (legacy_name), legacy_value);
		g_object_notify (object, NM_SETTING_BOND_OPTIONS);
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingBond *setting = NM_SETTING_BOND (object);
	NMSettingBondPrivate *priv = NM_SETTING_BOND_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_INTERFACE_NAME:
		g_value_set_string (value, nm_setting_bond_get_interface_name (setting));
		break;
	case PROP_MODE:
		g_value_set_string (value, nm_setting_bond_get_mode (setting));
		break;
	case PROP_MIIMON:
		g_value_set_int (value, nm_setting_bond_get_miimon (setting));
		break;
	case PROP_DOWNDELAY:
		g_value_set_int (value, nm_setting_bond_get_downdelay (setting));
		break;
	case PROP_UPDELAY:
		g_value_set_int (value, nm_setting_bond_get_updelay (setting));
		break;
	case PROP_ARP_INTERVAL:
		g_value_set_int (value, nm_setting_bond_get_arp_interval (setting));
		break;
	case PROP_ARP_IP_TARGET:
		g_value_set_boxed (value, nm_setting_bond_get_arp_ip_target (setting));
		break;
	case PROP_ARP_VALIDATE:
		g_value_set_string (value, nm_setting_bond_get_arp_validate (setting));
		break;
	case PROP_PRIMARY:
		g_value_set_string (value, nm_setting_bond_get_primary (setting));
		break;
	case PROP_PRIMARY_RESELECT:
		g_value_set_string (value, nm_setting_bond_get_primary_reselect (setting));
		break;
	case PROP_FAIL_OVER_MAC:
		g_value_set_string (value, nm_setting_bond_get_fail_over_mac (setting));
		break;
	case PROP_USE_CARRIER:
		g_value_set_int (value, nm_setting_bond_get_use_carrier (setting));
		break;
	case PROP_AD_SELECT:
		g_value_set_string (value, nm_setting_bond_get_ad_select (setting));
		break;
	case PROP_XMIT_HASH_POLICY:
		g_value_set_string (value, nm_setting_bond_get_xmit_hash_policy (setting));
		break;
	case PROP_RESEND_IGMP:
		g_value_set_int (value, nm_setting_bond_get_resend_igmp (setting));
		break;
	case PROP_OPTIONS:
		g_value_set_boxed (value, priv->options);
        break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_bond_class_init (NMSettingBondClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);
	guint i;

	g_type_class_add_private (setting_class, sizeof (NMSettingBondPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->get_virtual_iface_name = get_virtual_iface_name;

	/* Properties */
	/**
	 * NMSettingBond:interface-name:
	 *
	 * The name of the virtual in-kernel bonding network interface
	 **/
	props[PROP_INTERFACE_NAME].pspec =
	    g_param_spec_string (NM_SETTING_BOND_INTERFACE_NAME,
	                         "InterfaceName",
	                         "The name of the virtual in-kernel bonding network interface",
	                         NULL,
	                         G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:mode:
	 *
	 * The bonding mode. One of 'balance-rr', 'active-backup',
	 * 'balance-xor', 'broadcast', '802.3ad', 'balance-tlb', or
	 * 'balance-alb'.
	 **/
	props[PROP_MODE].pspec =
	    g_param_spec_string (NM_SETTING_BOND_MODE,
	                         "Mode",
	                         "The bonding mode",
	                         "balance-rr",
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:miimon:
	 *
	 * The MII link monitoring frequency, in milliseconds. Either this
	 * or #NMSettingBond:arp-interval should be set, and they can't
	 * both be set.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_MIIMON].pspec =
	    g_param_spec_int (NM_SETTING_BOND_MIIMON,
	                       "miimon",
	                       "The MII link monitoring frequence",
	                       0, G_MAXINT, 100,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:downdelay:
	 *
	 * The time, in milliseconds, to wait before disabling a slave
	 * after it goes down. Only valid if #NMSettingBond:miimon is
	 * non-0.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_DOWNDELAY].pspec =
	    g_param_spec_int (NM_SETTING_BOND_DOWNDELAY,
	                       "downdelay",
	                       "downdelay",
	                       0, G_MAXINT, 0,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:updelay:
	 *
	 * The time, in milliseconds, to wait before enabling a slave
	 * after it comes up. Only valid if #NMSettingBond:miimon is
	 * non-0.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_UPDELAY].pspec =
	    g_param_spec_int (NM_SETTING_BOND_UPDELAY,
	                       "updelay",
	                       "updelay",
	                       0, G_MAXINT, 0,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:arp-interval:
	 *
	 * The ARP-based link monitoring frequency, in milliseconds.
	 * Either this or #NMSettingBond:miimon should be set, and they
	 * can't both be set.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_ARP_INTERVAL].pspec =
	    g_param_spec_int (NM_SETTING_BOND_ARP_INTERVAL,
	                      "ARP interval",
	                      "The ARP-based link monitoring frequence",
	                       0, G_MAXINT, 0,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:arp-ip-target:
	 *
	 * An array of IPv4 addresses to ping when using ARP-based link monitoring.
	 * This only has an effect when #NMSettingBond:arp-interval is also set.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_ARP_IP_TARGET].pspec =
	    g_param_spec_boxed (NM_SETTING_BOND_ARP_IP_TARGET,
	                        "ARP IP target",
	                        "ARP monitoring target IP addresses",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:arp-validate:
	 *
	 * Specifies whether or not ARP probes and replies should be
	 * validated in the active-backup mode. One of
	 * 'none', 'active', 'backup', 'all'.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_ARP_VALIDATE].pspec =
	    g_param_spec_string (NM_SETTING_BOND_ARP_VALIDATE,
	                         "arp-validate",
	                         "Specifies whether or not ARP probes and replies should "
	                         "be validate in the active-backup mode",
	                         "none",
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:primary:
	 *
	 * The primary interface to use in 'active-backup' mode.
	 **/
	props[PROP_PRIMARY].pspec =
	    g_param_spec_string (NM_SETTING_BOND_PRIMARY,
	                         "Primary",
	                         "The primary interface",
	                         NULL,
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:primary-reselect:
	 *
	 * Specifies the reselection policy for the primary slave.
	 * One of 'always', 'better', 'failure'.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_PRIMARY_RESELECT].pspec =
	    g_param_spec_string (NM_SETTING_BOND_PRIMARY_RESELECT,
	                         "primary-reselect",
	                         "Specifies the reselection policy for the primary slave",
	                         "always",
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:fail-over-mac:
	 *
	 * Specifies whether active-backup mode should set all slaves to
	 * the same MAC address at enslavement (the traditional
	 * behavior), or, when enabled, perform special handling of the
	 * bond's MAC address in accordance with the selected policy.
	 * One of 'none', 'active', 'follow'.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_FAIL_OVER_MAC].pspec =
	    g_param_spec_string (NM_SETTING_BOND_FAIL_OVER_MAC,
	                         "fail-over-mac",
	                         "fail_over_mac",
	                         "none",
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:use-carrier:
	 *
	 * Specifies whether or not miimon should use MII or ETHTOOL
	 * ioctls vs. netif_carrier_ok() to determine the link
	 * status.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_USE_CARRIER].pspec =
	    g_param_spec_int (NM_SETTING_BOND_USE_CARRIER,
	                       "use-carrier",
	                       "use_carrier",
	                       0, 1, 1,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:ad-select:
	 *
	 * Specifies the 802.3ad aggregation selection logic to use.
	 * One of 'stable', 'bandwidth', or 'count'.
	 **/
	props[PROP_AD_SELECT].pspec =
	    g_param_spec_string (NM_SETTING_BOND_AD_SELECT,
	                         "ad-select",
	                         "ad_select",
	                         "stable",
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:xmit-hash-policy:
	 *
	 * Selects the transmit hash policy to use for slave selection in
	 * balance-xor and 802.3ad modes. One of 'layer2', 'layer2+3',
	 * 'layer3+4', 'encap2+3', or 'encap3+4'.
	 *
	 **/
	props[PROP_XMIT_HASH_POLICY].pspec =
	    g_param_spec_string (NM_SETTING_BOND_XMIT_HASH_POLICY,
	                         "xmit-hash-policy",
	                         "xmit_hash_policy",
	                         "layer2",
	                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:resend-igmp:
	 *
	 * Specifies the number of IGMP membership reports to be issued after
	 * a failover event. One membership report is issued immediately after
	 * the failover, subsequent packets are sent in each 200ms interval.
	 *
	 * The valid range is 0 - 255; the default value is 1. A value of 0
	 * prevents the IGMP membership report from being issued in response
	 * to the failover event.
	 *
	 * Since: 0.9.10
	 **/
	props[PROP_RESEND_IGMP].pspec =
	    g_param_spec_int (NM_SETTING_BOND_RESEND_IGMP,
	                       "resend-igmp",
	                       "resend_igmp",
	                       0, 255, 1,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE);

	/**
	 * NMSettingBond:options:
	 *
	 * Dictionary of key/value pairs of bonding options.  Both keys
	 * and values must be strings. Option names must contain only
	 * alphanumeric characters (ie, [a-zA-Z0-9_).
	 *
	 * Deprecated: use the specific properties
	 **/
	props[PROP_OPTIONS].pspec =
	    _nm_param_spec_specialized (NM_SETTING_BOND_OPTIONS,
	                                "Options",
	                                "Dictionary of key/value pairs of bonding "
	                                "options.  Both keys and values must be "
	                                "strings.  Option names must contain only "
	                                "alphanumeric characters (ie, [a-zA-Z0-9_]).",
	                                DBUS_TYPE_G_MAP_OF_STRING,
	                                G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE);

	/* Skip PROP_0 */
	for (i = 1; i < LAST_PROP; i++)
		g_object_class_install_property (object_class, i, props[i].pspec);
}
