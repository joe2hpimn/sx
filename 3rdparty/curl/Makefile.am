#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = CHANGES COPYING maketgz Makefile.dist curl-config.in	\
 RELEASE-NOTES buildconf libcurl.pc.in MacOSX-Framework \
 $(CMAKE_DIST) lib/libcurl.vers.in          \
 buildconf.bat include

CLEANFILES = $(VC6_LIBDSP) $(VC6_SRCDSP) $(VC7_LIBVCPROJ) $(VC7_SRCVCPROJ)	\
 $(VC71_LIBVCPROJ) $(VC71_SRCVCPROJ) $(VC8_LIBVCPROJ) $(VC8_SRCVCPROJ)	\
 $(VC9_LIBVCPROJ) $(VC9_SRCVCPROJ) $(VC10_LIBVCXPROJ) $(VC10_SRCVCXPROJ)	\
 $(VC11_LIBVCXPROJ) $(VC11_SRCVCXPROJ) $(VC12_LIBVCXPROJ) $(VC12_SRCVCXPROJ)	\
 $(VC14_LIBVCXPROJ) $(VC14_SRCVCXPROJ)

SUBDIRS = lib
DIST_SUBDIRS = $(SUBDIRS)

# List of files required to generate VC IDE .dsp, .vcproj and .vcxproj files
include lib/Makefile.inc
