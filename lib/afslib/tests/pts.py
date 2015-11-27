#coding: utf-8

import sys
sys.path.append("/opt/UD2/lib/afslib")




import afslib
import os

pts = afslib.ProtectionServer()

print(pts.user)
print(pts.group)

# pts.createuser("hoehle",-12)
# pts.createuser("",2)
# pts.createuser("core",2)
# pts.createuser("core2",2)

pts.createuser("core2",20)
print(pts.user)
print(os.popen("pts listent -user").read())

pts.deleteuser("core2")
print(pts.user)
print(os.popen("pts listent -user").read())



