## Process this with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

SUBDIRS = net timing

lib_LTLIBRARIES = libshout.la

noinst_HEADERS = 
libshout_la_SOURCES = shout.c

libshout_la_LIBADD = net/libicenet.la timing/libicetiming.la

INCLUDES = -I../include/shout -Inet -Itiming

# SCCS stuff (for BitKeeper)
GET = true

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
