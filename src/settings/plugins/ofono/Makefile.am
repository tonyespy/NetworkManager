SUBDIRS = .

@GNOME_CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/platform \
	-I$(top_srcdir)/src/settings \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-DNETWORKMANAGER_COMPILATION \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	$(DBUS_CFLAGS) \
	-DG_LOG_DOMAIN=\""NetworkManager-ofono"\" \
	-DSYSCONFDIR=\"$(sysconfdir)\"

noinst_LTLIBRARIES = libofono-io.la

libofono_io_la_SOURCES = \
	parser.c \
	parser.h

pkglib_LTLIBRARIES = libnm-settings-plugin-ofono.la

libnm_settings_plugin_ofono_la_SOURCES = \
	$(BUILT_SOURCES) \
	nm-ofono-connection.c \
	nm-ofono-connection.h \
	plugin.c \
	plugin.h

libnm_settings_plugin_ofono_la_LDFLAGS = -module -avoid-version
libnm_settings_plugin_ofono_la_LIBADD = libofono-io.la

CLEANFILES = $(BUILT_SOURCES)
