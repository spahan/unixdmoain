#!/bin/env python2
#coding: utf-8
"""iPlanet ldap server does not allow us to read more than 4000 records in one step. We could change this on the server-side via i.e. sizelimit=-1 but
imagine that you may not have the appropriate access to the ldap server, or that - we the admins - do not want to enable everybody to read all entries ;) 

Anyway to not mess too much around with this problem AND because it's a well known problem in querying large ldap databases
we work with pattern matches. We're generating a patternlist from "aaa ... to ... ZZZ", split this into 141 slices of 1000 queries and then
do query the ldap server with asynchronous "query-waves". 
The results are then added to our local berkeley DB if they do not already exist there. Berkeley DB becaus it's a really fast one and we need to lookup
for every UID key in this database while adding new UID's - so we need some performance for this lookups.

Also when the caching berkeley DB is built up we can use this one for creating the homedirectories instead of bothering around with all the ldap code.

walkthrough: 
create uid-pattern-slices
async query ldap for patterns and 
    - sync all users into caching berkeley DB 
    - sync all homedrives into caching berkeley DB
    - sync all gecos into caching berkeley DB

!! reverse check (are all UID's in berkeley DB still existent in LDAP ) is - NOT YET IMPLEMENTED - but MUST BE !!!

close ldap stuff
switch to homedrivetype (either AFS or NFSv4 or localHome)
sync homedrives (verify, add, remove)


for dn,e in a.conn.search_s(a.base, 2, "(uid=trau*)", ["uid", "uidNumber" ,"homeDirectory","gecos"]): print e


special keys/values:

key   : __created__ - DB creation date
value : __removed__ - uidNumberDB value to indicate a user that exists in DB but not in ldap anymore, in 2nd run this uid(key) will be removed"""




import anydbm
#import string
import sys
from datetime import datetime
from copy import copy
import logging



class dbmNode(object):
    def __init__(self, dbpath="/tmp"):
        self.uidNumberDB = dbopen(DBFILE="%s/uidNumber.db" % dbpath)
        self.homeDirDB = dbopen(DBFILE="%s/homeDir.db" % dbpath)
        self.gecosDB = dbopen(DBFILE="%s/gecos.db" % dbpath)
        self.uDB = self.uidNumberDB[0]
        self.hDB = self.homeDirDB[0]
        self.gDB = self.gecosDB[0]
        self.uidSEEN = copy(self.uDB.keys())

    def __str__(self):
        res = ""
        for db, dbname in [self.uidNumberDB, self.homeDirDB, self.gecosDB]:
            res += ("DB \'%s\' has %d records and was created %s.\n" % (dbname, len(db.keys()), db["__created__"])  )
        return(res)

    def keys(self):
        return(self.uDB.keys())

    def __getitem__(self, key):
        return( (self.hDB[key], self.uDB[key]) )

    def append(self, entry):
        """
        all attributes from an posixAccount that we parse here are single-value fields !
        to take always the first value from the entry-list must be correct as there can not be any multi-value per entry
        """
        uid = entry["uid"][0]
        if not uid in self.uidSEEN:
            self.uidSEEN.append(uid)
        self.uDB[uid] = str(entry["uidNumber"][0])
        self.hDB[uid] = str(entry["homeDirectory"][0])
        self.gDB[uid] = str(entry["gecos"][0])

    def remove(self, uid):
        self.uDB.pop(uid)
        try:
            self.hDB.pop(uid)
        except KeyError: 
            pass
        try:
            self.gDB.pop(uid)
        except KeyError: 
            pass
       
    def close(self): 
        self.uDB.close()
        self.hDB.close()
        self.gDB.close()

    def __del__(self):
        self.close()



def dbopen(DBFILE="/tmp/any.dbm"):
    def initDB(DBFILE):
        logging.warning("%s does not exist, initialize new DB", DBFILE)
        d = anydbm.open(DBFILE, "c")
        d["__created__"] = str(datetime.now())
        d.close()
    try:
        return(anydbm.open(DBFILE, "w"), DBFILE)
    except anydbm.error:
        initDB(DBFILE)
        return(anydbm.open(DBFILE, "w"), DBFILE)


def uidslices():
    """ 
    create all possible patterns from "aaa ... to ... ZZZ" and pack into 141 slices a 1000 patterns
    this is later used for querying the LDAP server in waves of 1000 asynchronous requests per query
    """ 
    ltrs = string.letters
    patternlist = [''.join([a, b, c]) for a in ltrs for b in ltrs for c in ltrs]
    return(slicelist(patternlist))


def ldapquery(princ, slice, db):
    qres = []
    #logging.debug("send %d asynchronous \"uid=pattern*\" queries to the ldap server %s ..." % (len(slice), princ) )
    for e in slice:
        #qres.append(princ.conn.search(princ.authen, 1, "(uid=%s*)" % e, ["uid", "uidNumber", "homeDirectory", "gecos"]) )
        #FIXME: dbbackend requires a userlookup for ldap (authen already has)
        qres.append(princ.conn.search(princ.config.ldapauthen, 1, "(uid=%s*)" % e, ["uid", "uidNumber", "homeDirectory", "gecos"]) )
  
    #logging.debug("add unknown uid values to our local caching berkeley DB ...")
    for res in qres:
        null, result = princ.conn.result(res)
        if result:
            for dn, entry in result:
                db.append(entry)


def slicelist(longlist, s_size=1000):
    """ split a longlist into slices of 1000 """
    slices = []
    null = [ slices.append(longlist[(e*s_size):(e*s_size)+s_size]) for e in range(0,(len(longlist)/s_size)+1) ]
    return(slices)


def sync_dbm2ldap(princ, db):
    """
    we need to use slicing again (1000 records per query)
    """
    uidlist = db.uDB.keys()
    uidlist.remove("__created__")
    uidlist.sort()
    slices = slicelist(uidlist, s_size=400)

    res_slices = []
    for slic in slices:
        logging.info("---- reverse test (dbm-cached uid) on uid-slice (%s - %s)\t no. %d (%d async ldap requests) ----", (slic[0], slic[-1], slices.index(slic), len(slic)) )
        reslist = []
        for uid in slic:
            # print("test uid %s (%d)" % (uid, uidlist.index(uid)))
            #reslist.append( princ.conn.search(princ.authen, 1, "(uid=%s)" % uid) )
            #FIXME: dbbackend requires userlookup
            reslist.append(princ.conn.search(princ.config.ldapauthen, 1, "(uid=%s)" % uid) )

        zipped = zip(reslist, slic)
        for res, uid  in zipped:
            null, result = princ.conn.result(res)
            if not result: 
                logging.debug("-------------- uid \'%s\' missing in ldap", uid)
                if db.uDB[uid] == "__removed__":
                    logging.debug("---- > %s already marked for remove, cleanup definitiv from cache", uid)
                    db.remove(uid)
                else:
                    db.uDB[uid] = "__removed__"

    
def cleanup_removed(db):
    for key in db.keys():
        if db[key][1] == "__removed__":
            db.remove(key)


def update_dbm(princ, db):
    """
    main routine for create and/or update the local caching db
    needs a princ object to authenticate and read the ldap server and a dbmNode object for the cache
    """
    slices = uidslices()

    # forward, from ldap to dbm
    for slic in slices:
        sys.stdout.write( "++++ query uid-pattern-slice (%s - %s) no: %d running (%d requests), cache DB knows  " % (slic[0], slic[-1], slices.index(slic), len(slic)) )
        ldapquery(princ, slic, db)
        logging.debug(" %d UID entries ++++ ", len(db.uidSEEN))
    # reverse, from dbm to ldap
    sync_dbm2ldap(princ, db)
  
    logging.info("\n==== ldap < -- > dbm sync finished. ====\n") 

