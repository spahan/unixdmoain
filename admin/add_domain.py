#!/usr/bin/env python2
# coding: utf-8 
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
"""
Script to create a new domain structure in the database backend.
"""
from getpass import getpass
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser


if __name__ == "__main__":
    #using optparse to parse args
    parser = OptionParser(usage="usage: %prog [options] domainName", description="generate a new domain structure.")
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account", default=False)
    parser.add_option("-a", action="store_true", dest="add_admin", help="create a domad for this domain. The user will be asked for details", default=False)
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
    #We have db conenctions from here.
    logging.info("writing new domain structure in %s \n" % args[0])
    if not db.init_domain(args[0]):
        print 'Error: Failure while initializing domain. check db-backend to see what happened.'
        sys.exit(1)
    if not options.add_admin:
        sys.exit(0)
    add_domad.add_domad(authen, args[0], False, db)
