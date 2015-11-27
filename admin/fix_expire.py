#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
script to add domads to a domain.
"""
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser
import subprocess
import os
import re

def fix_expire(authen, fnull=None):
    """look for hosts with wrong expire date. fix them.
    authen shall be a authenticated admin object
    fnull shall be a file object where the output of kadmin goes (either /dev/null or stdout)."""
    princs = subprocess.Popen(authen.kadm + ['-q', 'list_principals host/*'], stdout=subprocess.PIPE, stderr=fnull)
    valid_princ = re.compile(r'\w+/\w[\w\.-]*\w@[\w\.]+$')
    for line in princs.stdout:
        princ = line.strip()
        if (not valid_princ.match(princ)):
            continue
        if options.check_sub:
            host = princ.split('/',1)[1].split('@',1)[0]
            sub = subprocess.Popen(authen.kadm + ['-q', 'list_principals */%s@*' % host], stdout=subprocess.PIPE, stderr=fnull)
            for sub_line in sub.stdout:
                sub_princ = sub_line.strip()
                if (not valid_princ.match(sub_princ)):
                    continue
                logging.info('updating pwexpire for %s' % sub_princ)
                subprocess.call(authen.kadm + ['-q', 'modify_principal -pwexpire never %s' % (sub_princ)], stdout=fnull, stderr=fnull)
        else:
            logging.info('updating pwxpire for %s' % (princ))
            subprocess.call(authen.kadm + ['-q', 'modify_principal -pwexpire never host/%s@*' % (princ)], stdout=fnull, stderr=fnull)
    #fix_permission(authen, options.check_sub, fnull)
    if fnull: fnull.close()

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options]", description="""
search for host with a pwexpire and set it to none
This is a temprary fix.
""")
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account", default=False)
    parser.add_option("-v", action="store_true", dest="debug", help="be verbose", default=False)
    parser.add_option("-q", action="store_true", dest="quiet", help="be quiet", default=False)
    parser.add_option("-s", action="store_false", dest="check_sub", help="disable checking of subprincipals (for ex. nfs/host", default=True)
    (options, args) = parser.parse_args()
    fnull = open(os.devnull, 'w')
    if not options.debug and not options.quiet:
        logging.basicConfig(level=logging.INFO)
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
        fnull=None
    if options.quiet:
        logging.basicConfig(level=logging.FATAL)
        
    if options.janitor:
        config = Classes.Config(krb5keytab="/root/janitor/janitor.keytab",plugin_author='ldapdbadmin')
    else:
        config = Classes.Config(plugin_authen="krb5_login", plugin_author='ldapdbadmin')
    authen = Classes.Authen(config)
    if not authen:
        sys.exit(3)
    userid = authen.authenticate()
    authen.kadmin()
    fix_expire(authen,fnull)

