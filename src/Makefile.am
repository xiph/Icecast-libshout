## Process this with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

SUBDIRS = net timing

lib_LTLIBRARIES = libshout.la

noinst_HEADERS = 
libshout_la_SOURCES = shout.c util.c vorbis.c mp3.c

libshout_la_LIBADD = net/libicenet.la timing/libicetiming.la

INCLUDES = -I$(top_srcdir)/include/shout -I$(srcdir)/net -I$(srcdir)/timing

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
