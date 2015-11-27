#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
script to list hosts
"""
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser
import datetime
import time # required as datetime has no strptime in python < 2.5
import ldap

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] [days]", description="""
search for hosts who did not report back within [days]. default is 4 weeks""")
    parser.add_option("-v", action="store_true", dest="debug", help="be verbose", default=False)
    (options, args) = parser.parse_args()
    if len(args) > 1:
        parser.print_help()
        sys.exit(2)
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    
    if len(args) == 0:
        delta = datetime.timedelta(weeks=4)
    else:
        delta = datetime.timedelta(days=int(args[0]))

    config = Classes.Config(plugin_authen='krb5_login', plugin_author='ldapdbadmin')
    authen = Classes.Authen(config)
    if not authen:
        sys.exit(3)
    userid = authen.authenticate()
    if not userid:
        sys.exit(4)
    author = Classes.Author(config)
    if not author:
        sys.exit(3)
    db = author.authorize(userid.split('@')[0])
    if not db:
        sys.exit(4)

    print 'The following hosts have not been seen in the last %s days:' % delta.days
    res = db.conn.result(db.conn.search(config.ldapbase, ldap.SCOPE_SUBTREE, '(&(objectClass=udHost)(lastSeen<=%s))'%((datetime.date.today() - delta).strftime("1%y%m%d00")) , ['cn', 'FQDN', 'USID', 'description', 'lastSeen']))[1]
    res.sort(key=lambda x: int(x[1]['lastSeen'][0]))
    for (dn, att) in res:
        print time.strftime("%d %b %Y", time.strptime(att['lastSeen'][0],"1%y%m%d%H")), ' : ', att['FQDN'][0]

