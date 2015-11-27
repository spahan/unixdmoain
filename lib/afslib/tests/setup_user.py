#coding: utf-8

"""
test setup user
"""

import sys
sys.path.append("/opt/UD2/lib/afslib")



import afslib


userHome_fileserver = ("urz-mars.urz.unibas.ch", "/vicepa")

user = ("core2", "1241", "/afs/.cus.urz.unibas.ch/user/testuser/core2")
afslib.setup_user(user, userHome_fileserver, quota=200000)



