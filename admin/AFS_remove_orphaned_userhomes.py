#!/usr/bin/env python2
#coding: utf-8

import sys
import UniDomain.UniDomain as UniDomain
import UniDomain.afslib.afslib as afslib
import UniDomain.afslib.urenew as urenew


KEYTAB = "/root/janitor/janitor.keytab"
roger = UniDomain.janitor(KEYTAB=KEYTAB)
urenew.aklog()
print("reading volume location database, please be patient ... ")
vos = afslib.VolumeServer()

print vos
print "Fileservers : %s " % str(vos.fileserv)

vos.cleanup_orphaned()


