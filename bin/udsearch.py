#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
query database about objects.

"""
#FIXME: Move me into ldap plugin. this should only be a interface to db-backend.
import sys
import ldap
import logging
from UniDomain import Classes
from optparse import OptionParser
EXCLUDES = ["sn", "objectClass", "userPassword" ]

if __name__ == "__main__": 
    parser = OptionParser(usage="usage: %prog [options] needle", description="search needles in database. needle must be at least 3 characters long")
    parser.add_option("-d", action="store_true", dest="debug", help="be verbose", default=False)
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.print_help()
        sys.exit(2)
    if len(args[0]) < 3:
        parser.print_help()
        sys.exit(2)
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
 
    config = Classes.Config()
    authen = Classes.Authen(config).authenticate()
    if not authen:
        logging.critical('authentication of this host failed. Is this host registered in a domain? Network is up?')
        sys.exit(1)
    # connect to database
    db = Classes.DB(authen).connect()
    if not db:
        logging.critical('can not connect to database.')
        sys.exit(3)
    # prepare search
    tmp = [
        ("(&(objectClass=posixAccount)(uid=%s*))" % args[0], config.ldapauthen),
        ("(&(objectClass=posixAccount)(cn=%s*))" % args[0], config.ldapauthen),
        ("(&(objectClass=posixAccount)(sn=%s*))" % args[0], config.ldapauthen),
        ("(&(objectClass=Person)(uid=%s*/domad))" % args[0], config.ldapbase),
        ("(&(objectClass=posixGroup)(cn=%s*))" % args[0], config.ldapauthen),
        ("(&(objectClass=udGroup)(cn=%s*))" % args[0], config.ldapbase),
        ("(&(objectClass=udHost)(cn=%s*))" % args[0], config.ldapbase),
        ("(&(objectClass=udHost)(USID=host/%s*))" % args[0], config.ldapbase),
        ("(|(&(objectClass=udDomain)(ou=%s*)) (&(objectClass=udHostContainer)(ou=%s*)))" % (args[0],args[0]), config.ldapbase)]
    reslist = [db.conn.search(dn, ldap.SCOPE_SUBTREE, filter) for (filter,dn) in tmp]
    dbdata = {}
    while len(reslist) > 0:
        (type, data, id) = db.conn.result2(ldap.RES_ANY, 0, config.ldaptimeout)
        if type == ldap.RES_SEARCH_RESULT:
            reslist.remove(id)
            continue
        if not data[0][0] in dbdata:
            dbdata[data[0][0]] = data[0][1]
    if len(dbdata) == 0:
        print "Nothing found"
        sys.exit(0)
    print "The database has this account informations (%i):" % len(dbdata)
    tablen = max([len(attname) for attlist in dbdata.values() for attname in attlist.keys()]) + 3
    counter = 0
    for (dn, attlist) in dbdata.items():
        counter += 1
        print "%3i: %s" % (counter, attlist[dn.split('=',1)[0]][0])
        for (at,vals) in attlist.items():
            if at in EXCLUDES: 
                continue
            print '\t%s : %s%s' % (at, ' '*(tablen-len(at)), ', '.join(vals)) 
        print '\tDN : %s%s' % (' '*(tablen-2), dn)
