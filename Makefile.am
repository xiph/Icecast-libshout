## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign

SUBDIRS = include src

EXTRA_DIST = README COPYING examples/Makefile examples/example.c

#install-data-local:
#	mkdir -p $(DESTDIR)$(includedir)/shout
	#mkdir -p $(DESTDIR)$(prefix)/doc/$(PACKAGE)-$(VERSION)/example
	#$(INSTALL) -m 0644 README AUTHORS COPYING CHANGES $(DESTDIR)$(prefix)/doc/$(PACKAGE)-$(VERSION)
	#$(INSTALL) -m 0644 example/Makefile example/example.c $(DESTDIR)$(prefix)/doc/$(PACKAGE)-$(VERSION)/example
	#$(INSTALL) -m 0644 shout.h $(DESTDIR)$(includedir)/shout


# SCCS stuff (for BitKeeper)
GET = true

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"
