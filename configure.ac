#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(UniDomain, 2.6, h.spalinger@stud.unibas.ch)
AM_INIT_AUTOMAKE(UniDomain, 2.6)
AM_PATH_PYTHON(2.4)

#admin tools
AM_CONDITIONAL(WITH_ADMIN, false)
AC_ARG_ENABLE(  [admin], 
                [  --enable-admin  build with admin tools ],
                [AM_CONDITIONAL(WITH_ADMIN, true)])

#www interface
AM_CONDITIONAL(WITH_WWWLIB, false)
AC_ARG_ENABLE(  [www], 
                [  --enable-www    build with www],
                [AM_CONDITIONAL(WITH_WWWLIB, true)])

AC_OUTPUT(Makefile bin/Makefile sbin/Makefile etc/Makefile admin/Makefile share/Makefile share/doc/Makefile lib/Makefile lib/plugins/Makefile lib/udPolicy/Makefile lib/afslib/Makefile wwwlib/Makefile wwwlib/html/Makefile wwwlib/html/images/Makefile)
