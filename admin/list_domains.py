#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
list all domains
i award this script the most useless script in this directory.
"""
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser


if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options]", description="""
list all domains. """)
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account", default=False)
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
    
    print("\nDomains hosted in this directory server : \n")
    print('\n'.join(['\t%s (%s) [%s]' % x for x in db.list_domains()]))
