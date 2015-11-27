#!/usr/bin/env python2
# coding: utf-8


"""

take results from dbm cache and create homedirectories on local files

"""



import UniDomain.UniDomain as UniDomain
import UniDomain.dbmcache as dbmcache
import os
import shutil


BASEDIR = "/test"
SKEL = "/etc/skel"


def create_home(dir, uid, uidNumber):
    print("%s does not exist, create new" % dir)
    homedir = dir.rstrip(uid)
    if not os.access(homedir, os.F_OK):
        os.makedirs(homedir)
    shutil.copytree(SKEL, dir)
    os.chown(dir, uidNumber, 0)
    os.chmod(dir, 0700)



def main():
    host = UniDomain.host()
    db = dbmcache.dbmNode(dbpath=host.config.cachedir)
    #FIXME: host/princ?
    dbmcache.update_dbm(host, db)
    db.close()

    db = dbmcache.dbmNode(dbpath=host.config.cachedir)
    print(db)
    keys = db.keys()
    keys.remove("__created__")

    print("verify existance of homedirectories under base \'%s\' " % BASEDIR)
    for uid in keys:
        dir, uidNumber = db[uid]
        dir = "%s/%s" % (BASEDIR, dir)
        if not uidNumber == "__removed__":
            uidNumber = int(uidNumber)
            if not os.access(dir, os.F_OK):
                create_home(dir, uid, uidNumber)
            else:
                os.chown(dir, uidNumber, 0)
                os.chmod(dir, 0700)
                # shutil.rmtree(dir)
        else: 
            print("%s is removed from ldap, remove %s" % (uid,dir))
            try:
                shutil.rmtree(dir)
            except OSError: pass



if __name__ == "__main__": main()



