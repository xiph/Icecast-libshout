## Process this with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

SUBDIRS = avl net timing httpp thread

lib_LTLIBRARIES = libshout.la

noinst_HEADERS = shout_private.h util.h
libshout_la_SOURCES = shout.c util.c vorbis.c mp3.c

libshout_la_LIBADD = net/libicenet.la timing/libicetiming.la avl/libiceavl.la\
		httpp/libicehttpp.la thread/libicethread.la

INCLUDES = -I$(top_srcdir)/include/shout -I$(srcdir)/net -I$(srcdir)/timing -I$(srcdir)/avl -I$(srcdir)/thread -I$(srcdir)/httpp

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
