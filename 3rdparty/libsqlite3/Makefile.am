noinst_LTLIBRARIES = libsqlite3.la
libsqlite3_la_SOURCES = sqlite3.c \
     	       sqlite3.h

libsqlite3_la_CPPFLAGS = $(AM_CPPFLAGS) -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0 @SQLITE3_FLAGS@
libsqlite3_la_LIBTOOLFLAGS = $(AM_LIBTOOLFLAGS) --tag=disable-shared

