## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign

includedir = $(prefix)/include/shout
include_HEADERS = shout.h

# SCCS stuff (for BitKeeper)
GET = bk get -Sq

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
