## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

noinst_PROGRAMS = example

example_SOURCES = example.c
example_LDADD = $(top_builddir)/src/libshout.la
AM_CFLAGS = @XIPH_CFLAGS@
AM_CPPFLAGS = @XIPH_CPPFLAGS@ -I$(top_builddir)/include
