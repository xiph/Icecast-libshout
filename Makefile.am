## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src examples

EXTRA_DIST = README COPYING m4/ac_config_libconfig_in.m4 m4/acx_pthread.m4 \
	m4/ogg.m4 m4/vorbis.m4
bin_SCRIPTS = shout-config

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = shout.pc

##install-data-local:
	##mkdir -p $(DESTDIR)$(includedir)/shout
	##mkdir -p $(DESTDIR)$(prefix)/doc/$(PACKAGE)-$(VERSION)/example
	##$(INSTALL) -m 0644 README AUTHORS COPYING CHANGES $(DESTDIR)$(prefix)/doc/$(PACKAGE)-$(VERSION)
	##$(INSTALL) -m 0644 example/Makefile example/example.c $(DESTDIR)$(prefix)/doc/$(PACKAGE)-$(VERSION)/example
	##$(INSTALL) -m 0644 shout.h $(DESTDIR)$(includedir)/shout

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
