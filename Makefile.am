## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src examples

EXTRA_DIST = INSTALL shout.m4 m4/ac_config_libconfig_in.m4 m4/acx_pthread.m4 \
	m4/gccinclude.m4 m4/ogg.m4 m4/vorbis.m4 m4/xiph_clean_ccflags.m4

docdir = $(datadir)/doc/$(PACKAGE)
doc_DATA = COPYING README examples/example.c

m4datadir = $(datadir)/aclocal
m4data_DATA = shout.m4

if HAVE_PKGCONFIG
  pkgconfigdir = $(libdir)/pkgconfig
  pkgconfig_DATA = shout.pc
else
  bin_SCRIPTS = shout-config
endif

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
