#!/usr/bin/env python2
# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
housekeeping jobs, run this script as cronjob.

Do not forget to change KEYTAB to the location where
your janitor.keytab file is.
"""

from UniDomain import Classes
import re

def detect_bad_hosts(authen, db):
    """Searches for hosts which are missing from ldap or kerberos.
    returns a array with problems."""
    problems = []
    krb_result = authen.list_hosts()
    ldap_result = db.conn.search_s(config.ldapbase, ldap.SCOPE_SUBTREE, '(ObjectClass=udHost)', ['USID', 'FQDN', 'cn'])
    ldap_hosts = set()
    for id,atts in ldap_result:
        # check primary attributes have single values. multiple ones indicate a unsuccessfull copy.
        for at in atts:
            if len(atts[at]) != 1:
                problems.append( "Warning: Host %s has multiple %s Attributes!" % (id,at) )
        if not id.startswith('cn=%s,' % atts['cn'][0]):
            problems.append( "Warning: Host id and cn differ for %s!" % id )
        if not atts['FQDN'][0].startswith('%s.' % atts['cn'][0]):
            problems.append( "Warning: FQDN (%s) does not start with hostname (%s) for %s!" % (atts['FQDN'][0],atts['cn'][0],id) )
        if not atts['FQDN'][0].endswith('.unibas.ch'):
            problems.append( "Info: Host %s (%s) is not in domain unibas.ch." % (id, atts['FQDN'][0]) )
        if not atts['USID'][0].startswith('host/%s@' % atts['FQDN'][0]):
            problems.append( "Warning: Host USID (%s) and hostname (%s) different for %s!" % (atts['USID'][0], atts['cn'][0], id) )
        if atts['FQDN'][0] in ldap_hosts:
            problems.append( "ERROR!!: FQDN of %s (%s) is already taken by another host!" % (id, atts['FQDN'][0]) )
        else:
            ldap_hosts.add(atts['FQDN'][0])
    krb_hosts = set()
    for host in krb_result:
        mo = re.match(r'host/([a-z0-9-.]*\.unibas\.ch)@UD.UNIBAS.CH', host)
        if mo:
            krb_hosts.add(mo.group(1))
        else:
            problems.append( "Warning: bad principal name for %s." % host )

    for bad in krb_hosts-ldap_hosts:
        problems.append( "Warning: host %s in kerberos but not in ldap!" % bad )
    for bad in ldap_hosts-krb_hosts:
        problems.append( "Warning: host %s in ldap but not in kerberos!" % bad )
    return problems

def main():
    config = Classes.Config(krb5keytab="/root/janitor/janitor.keytab",plugin_author='ldapdbadmin')
    authen = Classes.Authen(config)
    if not authen:
        print "bad auth"
        return
    userid = authen.authenticate(user='janitor/admin')
    if not userid: return
    authen.kadmin()
    author = Classes.Author(config)
    db = author.authorize('janitor/admin')
    
    config = Classes.Config(krb5keytab="/root/janitor/janitor.keytab",plugin_author='ldapdbadmin')
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
        
    db.update_dnsSOA()
    #FIXME: implement this.
    #roger.search_expiredHosts()

if __name__ == "__main__": 
    main()
