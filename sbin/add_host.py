#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
script to add a host to ldap and/or kerberos.
this is a helper for host with heimdal kerberos who can not get keytab entries with kadmin
"""
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser
import hostreg
        
if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] [host1 [host2 [host3 [...]]]] ", description="""
add hosts to the ud2 system. host must be specified as FQDNs.
This script does 2 things:
1. add a principal to the kdc. This requires a domad ticket or a janitor ticket.
2. retreive the keytab into a local keytab to transfer to the target.
returns:
 2 if no hosts are given
 3 if Instantiation of Objects failed
 4 bad credentials
""")
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account.", default=False)
    parser.add_option("-v", action="store_true", dest="debug", help="be verbose", default=False)
    parser.add_option("-p", action="store_false", dest="add_kdc", help="assume the principal already exists in the kdc. Just retrieve the key to the local keytab", default=True)
    parser.add_option("-l", action="store_false", dest="add_ldap", help="assume the host already exists in the ldap.", default=True)
    (options, args) = parser.parse_args()
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    if len(args) < 1:
        sys.exit(2)
     
    if options.janitor:
        config = Classes.Config(krb5keytab="/root/janitor/janitor.keytab")
    else:
        config = Classes.Config(plugin_authen="krb5_login")
    authen = Classes.Authen(config).authenticate()
    if not authen:
        print 'Authentication error'
        sys.exit(4)
    db = Classes.DB(authen).connect()
    if not db:
        print 'db connection error'
        sys.exit(3)

    print '***%s***' % args
    for host in args:
        print 'Adding %s:' % host
        target = hostreg.askTarget(db)
        classes = hostreg.askClasses()
        policies = hostreg.askPolicies()
        args = {}
        if len(policies) > 0:
            args['cfPolicy'] = ('policyClass',policies)
        logging.debug('adding %s to %s' % (host, target))
        if options.add_ldap:
            if not db.add_host(host, target, classes, **args):
                logging.error('cant add %s to ldap', host)
                continue
        if options.add_kdc:
            if not authen.add_service('host', host):
                logging.critical('cant add host to authen. (but host was added to database!)', host)
                continue
            if not authen.add_service('nfs', host):
                logging.warning('cant add nfs principal for %s to authen.', host)
        if not authen.get_service_keytab('host', host, '', 'krb5.keytab_%s' % host):
            logging.critical('cant get host keytab for %s', host)
            continue
        if not authen.get_service_keytab('nfs', host, '', 'krb5.keytab_%s' % host):
            logging.warning('cant get nfs keytab for %s', host)
            continue

