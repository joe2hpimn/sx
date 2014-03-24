# $Id: Makefile.am,v 1.9 2001/12/22 03:16:20 robs Exp $

INCLUDEDIR  = ../include
CPPFLAGS    = @CPPFLAGS@ -I$(top_srcdir)/include

INCLUDE_FILES = $(INCLUDEDIR)/fastcgi.h     \
                $(INCLUDEDIR)/fcgiapp.h     \
                $(INCLUDEDIR)/fcgimisc.h    \
                $(INCLUDEDIR)/fcgi_stdio.h  \
                $(INCLUDEDIR)/fcgios.h

lib_LTLIBRARIES   = libfcgi.la

libfcgi_la_SOURCES = $(INCLUDE_FILES)  \
                     fcgiapp.c         \
                     fcgi_stdio.c      \
                     os_unix.c
libfcgi_la_CC      = @PTHREAD_CC@
libfcgi_la_CFLAGS  = @PTHREAD_CFLAGS@
