dnl This file must follow autoconf m4 rules.  It is imported directly via
dnl autoconf.
dnl DESCRIPTION="(Development Release)"
dnl MAJORVER=9
dnl MINORVER=15
dnl PATCHVER=0
dnl RELEASETYPE=
dnl RELEASEVER=
dnl EXTENSIONS=

m4_define([bind_VERSION_MAJOR], 9)dnl
m4_define([bind_VERSION_MINOR], 15)dnl
m4_define([bind_VERSION_PATCH], 0)dnl
m4_define([bind_VERSION_EXTRA], -dev)dnl
m4_define([bind_DESCRIPTION], " (Development Release)")
m4_define([bind_SRCID], ["][m4_esyscmd_s([if test -f srcid; then cat srcid; else git rev-parse --short HEAD 2>/dev/null; fi])]["])dnl

m4_define([bind_PKG_VERSION], [[bind_VERSION_MAJOR.bind_VERSION_MINOR.bind_VERSION_PATCH]bind_VERSION_EXTRA])dnl
