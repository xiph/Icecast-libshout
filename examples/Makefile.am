## Process this file with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

noinst_PROGRAMS = example

example_SOURCES = example.c
example_LDADD = ../src/libshout.la $(OGG_LIBS) $(VORBIS_LIBS)
AM_CFLAGS = @XIPH_CFLAGS@

INCLUDES = -I$(top_srcdir)/include
