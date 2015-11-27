#!/usr/bin/env python2
# coding: utf-8


"""
take results from dbm cache and maintain AFS user, volumes, homepathes and mounts
"""

AFSHOME_fileserver = ("urz-mars.urz.unibas.ch", "/vicepa")
AFSHOME_basepath = "/afs/.cus.urz.unibas.ch/unibasHome/"
DEFAULT_QUOTA = 200000

KEYTAB = "/root/janitor/janitor.keytab"



import UniDomain.UniDomain as UniDomain
import UniDomain.afslib.afslib as afslib
import UniDomain.dbmcache as dbmcache
import UniDomain.afslib.urenew as urenew


def sync_DB(princ):
    db = dbmcache.dbmNode(dbpath=princ.config["cachedir"])
    dbmcache.update_dbm(princ, db)
    db.close()




def main():
    roger = UniDomain.janitor(KEYTAB=KEYTAB)
    urenew.aklog()
    sync_DB(roger)

    db = dbmcache.dbmNode(dbpath=roger.config["cachedir"])
    pts = afslib.ProtectionServer()
    vos = afslib.VolumeServer()

    print(vos)
    print(db)

    keys = db.keys()
    keys.remove("__created__")
    for uid in keys:
        print "\n>>>>", "-"*40, uid, "-"*40, "<<<<\n"
        user = (uid, db.uDB[uid], "%s%s" % (AFSHOME_basepath, db.hDB[uid]) )
        if not db.uDB[uid] == "__removed__":
            if not uid in pts.user.keys():
                print("%s must be created in pts " % uid)
                afslib.setup_user(pts, vos, user, AFSHOME_fileserver, quota=DEFAULT_QUOTA)
            else:
                print("%s already exists in pts, skip. " % uid)
        else:
            if not uid in pts.user.keys():
                print("%s already removed from pts, skip. " % uid)
            else:
                print("%s must be removed from pts and mountpathes." % uid)
                afslib.disable_user(pts, vos, user, AFSHOME_fileserver)
    print "\n","AFS sync has terminated."
    



    
        




if __name__ == "__main__": main()



