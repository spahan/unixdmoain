AUTOMAKE_OPTIONS = foreign
SUBDIRS = bin sbin share etc lib
sharedir = $(prefix)/share
share_DATA = LICENSE.TXT
if WITH_ADMIN
SUBDIRS += admin
endif
if WITH_WWWLIB
SUBDIRS += wwwlib
endif
