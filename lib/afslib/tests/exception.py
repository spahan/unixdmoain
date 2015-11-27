

import sys
sys.path.append("/opt/UD2/lib/afslib")




import afslib


try:
    raise afslib.AccessDenied("pts permission denied")
except afslib.AccessDenied, e:
    print e


try:
    raise afslib.AccessDenied
except afslib.AccessDenied, e:
    print e


