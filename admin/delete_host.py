#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
script to delete a host account
"""
import sys
import logging
from UniDomain import Classes
from UniDomain.functions import getlocalhostname
from optparse import OptionParser
        
if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] host", description="""
delete a host. 
host mst be a fqdn or 'localhost' for the local host.
if neither --authen nor --author are specified we try delete from both. 
Else we only delete from the one(s) specified""")
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account", default=False)
    parser.add_option("--authen", action="store_true", dest="authen", help="delete from authen backend (kerberos)", default=False)
    parser.add_option("--author", action="store_true", dest="author", help="list from database backend (ldap)", default=False)
    parser.add_option("-v", action="store_true", dest="debug", help="be verbose", default=False)
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.print_help()
        sys.exit(2)
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
        
    if options.janitor:
        config = Classes.Config(krb5keytab="/root/janitor/janitor.keytab",plugin_author='ldapdbadmin')
    else:
        config = Classes.Config(plugin_authen="krb5_login", plugin_author='ldapdbadmin')
    if not (options.author or options.authen):
        options.authen = True
        options.author = True
    authen = Classes.Authen(config)
    if not authen:
        sys.exit(3)
    userid = authen.authenticate()
    if not userid:
        sys.exit(4)
    authen.kadmin()
    author = Classes.Author(config)
    if not author:
        sys.exit(3)
    db = author.authorize(userid.split('@')[0])
    if not db:
        sys.exit(4)
    
    if options.authen:
        try:
            if not authen.delete_domad( args[0] ):
                print "Error deleting %s from authentication" % args[0]
            else:
                print "%s was removed from authentication backend." % args[0]
        except Exception:
            print "Error while try remove %s from the auhtentication backend." % args[0]
    if options.author:
        try:
            if not db.delete_domad( args[0] ):
                print "Error deleting %s from database" % args[0]
            else:
                print "%s was removed from the database" % args[0]
        except Exception:
            print "Error while removing %s from database." % args[0]
