#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
script to list domads
"""
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] [domain]", description="""
list domad accounts. 
Specify a domain implies --author
if neither --authen nor --author are specified we list from authentication and database """)
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account", default=False)
    parser.add_option("--authen", action="store_true", dest="authen", help="list from authen backend (kerberos)", default=False)
    parser.add_option("--author", action="store_true", dest="author", help="list from database backend (ldap)", default=False)
    parser.add_option("-v", action="store_true", dest="debug", help="be verbose", default=False)
    (options, args) = parser.parse_args()
    if len(args) > 1:
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
        sys.stdout.write("\nDomain Administrators in the authen backend. : \n")
        sys.stdout.write("\n".join(['\t%s' % da for da in authen.list_domad()]) + '\n')
    if options.author:
        if len(args) == 0:
            domainID = db.domainID
        else:
            domainID = db.get_itemID(args[0])
            if not domainID:
                sys.exit(5)
        sys.stdout.write("\nDomainAdministrators in the db backend : \n")
        sys.stdout.write('\n'.join(['\t%s\t%s; %s; %s' % vals for vals in db.list_domad(domain=domainID)]) + '\n')
