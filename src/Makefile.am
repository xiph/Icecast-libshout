## Process this with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

SUBDIRS = avl net timing httpp thread

lib_LTLIBRARIES = libshout.la
libshout_la_LDFLAGS = -version-info 3:0:0

noinst_HEADERS = shout_private.h util.h
libshout_la_SOURCES = shout.c util.c vorbis.c mp3.c

libshout_la_LIBADD = net/libicenet.la timing/libicetiming.la avl/libiceavl.la\
		httpp/libicehttpp.la thread/libicethread.la $(VORBIS_LIBS) $(OGG_LIBS)

INCLUDES = -I$(top_srcdir)/include/shout -I$(srcdir)/net -I$(srcdir)/timing -I$(srcdir)/avl -I$(srcdir)/thread -I$(srcdir)/httpp $(VORBIS_CFLAGS) $(OGG_CFLAGS)

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
