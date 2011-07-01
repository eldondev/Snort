#!/bin/sh
# the list of commands that need to run before we do a compile
rm -f ltmain.sh aclocal.m4 config.h.in config.guess config.sub install-sh missing ylwrap depcomp configure
rm -fr autom4te.cache
find . -name Makefile.in -exec rm -f {} \;
libtoolize --automake --copy
aclocal -I m4 ${SNORT_ACLOCAL_ARGS}
autoheader
automake --add-missing --copy
autoconf
