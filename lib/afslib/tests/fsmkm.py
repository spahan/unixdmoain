#coding: utf-8

import sys
sys.path.append("/opt/UD2/lib/afslib")




import afslib

vos = afslib.VolumeServer()

print vos
print "Fileservers : %s " % str(vos.fileserv)


testvol = ("testvolume", "urz-mars.urz.unibas.ch", "/vicepa")

vos.create(testvol)


testpath = "/afs/.cus.urz.unibas.ch/users/testvol"

afslib.fs_mkm(testpath, testvol[0])

import os
print(os.popen("ls -ltra /afs/.cus.urz.unibas.ch/users").read() )


afslib.fs_rmm(testpath)
vos.remove(testvol)

print(os.popen("ls -ltra /afs/.cus.urz.unibas.ch/users").read() )

