#!/usr/bin/python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
script to setup nfs4
"""
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser
        

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] [host1 [host2 [host3 [...]]]] ", description="""
setup key for nfs usage.
This script does 2 things:
1. add a principal to the kdc. This requires a domad ticket or a janitor ticket.
   if host is provided, this will create principals for each of them. Else we add a principal for the local host.
2. retrieve the key and store it in the system keytab. This may be done using the local host keytab.
providing hosts implies the -n option!
returns:
 3 if Instantiation of Objects failed
 4 bad credentials
""")
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account. This implies the -n option", default=False)
    parser.add_option("-d", action="store_true", dest="debug", help="be verbose", default=False)
    parser.add_option("-n", action="store_false", dest="get_keytab", help="do not retrieve the created key into the system keytab (usefull to add principals from a central authority).", default=True)
    parser.add_option("-p", action="store_false", dest="add_kdc", help="assume the principal already exists in the kdc. Just retrieve the key to the local keytab", default=True)
    (options, args) = parser.parse_args()
    #if len(args) > 0:
    #    # do not get keytab if we maualy add hosts.
    #    options.get_keytab = False
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
     
    # get the correct rights.
    # if we only want retrieve the key file, we only require host privileges.
    if options.add_kdc:
        if options.janitor:
            config = Classes.Config(krb5keytab="/root/janitor/janitor.keytab")
            # janitor operation assumes we want add host principals without getting the key to the local keytab.
            options.get_keytab = False
        else:
            config = Classes.Config(plugin_authen="krb5_login")
    else:
        config = Classes.Config()
    authen = Classes.Authen(config)
    if not authen:
        sys.exit(3)
    userid = authen.authenticate()
    if not userid:
        sys.exit(4)
    authen.kadmin()
    
    if options.add_kdc:
        if len(args) == 0:
            authen.add_service_principal('nfs', '-e des-cbc-crc:normal')
        else:
            for host in args:
                if not authen.add_service_principal('nfs/%s@%s' % (host, config.krb5realm), '-e des-cbc-crc:normal'):
                    logging.warning('failed to add %s to kdc!' % (host))

    if options.get_keytab:
        if len(args) == 0:
            authen.get_service_keytab('nfs', '-e des-cbc-crc:normal')
        else:
            for host in args:
                logging.debug('getting key for %s', host)
                if not authen.get_service_keytab('nfs/%s@%s' % (host, config.krb5realm), '-e des-cbc-crc:normal', keytab='./krb5.keytab_'+host):
                    logging.warning('failed to retrieve nfs service key for %s' ,host)

