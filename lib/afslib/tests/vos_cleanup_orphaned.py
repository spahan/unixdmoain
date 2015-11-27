#coding: utf-8

import sys
sys.path.append("/opt/UD2/lib/afslib")




import afslib

vos = afslib.VolumeServer()

# for vol in vos.volumes:
#     print vol

print vos
print "Fileservers : %s " % str(vos.fileserv)



vos.cleanup_orphaned()



