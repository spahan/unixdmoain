#coding: utf-8

import sys
sys.path.append("/opt/UD2/lib/afslib")




import afslib

vos = afslib.VolumeServer()

# for vol in vos.volumes:
#     print vol

print vos
print "Fileservers : %s " % str(vos.fileserv)


testvol = ("testvolume", "urz-mars.urz.unibas.ch", "/vicepa")

vos.create(testvol)

import os
print(os.popen("vos exa testvolume").read())
vos.remove(testvol)


