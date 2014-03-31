#!/bin/sh
#
# $Id: autogen.sh,v 1.6 2004/09/16 12:32:24 bazsi Exp $
#
# Run this script to generate Makefile skeletons and configure
# scripts.
#

libtoolize -f
aclocal
autoheader
autoconf
automake --add-missing --foreign
