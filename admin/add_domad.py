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
from getpass import getpass
import sys
import logging
from UniDomain import Classes
from optparse import OptionParser
        
def add_domad(authen, domain_name='', domad_uid='', db=False, domad_pwd='passw0rd', domad_fullname='Domain Administrator' ):
    """
    add a domad to a domain.
    This will ask for domad details and adds it.
    @param authen: a logged in authen object.
    @type authen: Classes.Authen
    @param db: A db backend object. if not set, we dont add the domad to the db-backend.
    @param domain_name: the domain where we want add this domad.
    @param domad_uid: uid for this domad, if not set, we ask for it.
    @param domad_pwd: for sake of automatisation we have this nice parameter to st the users password. NEVER USE! You have been warned.
    @param domad_fullname: The full name of this domain administrator.
    @return: True if successfully created the domad, False otherwise.
    """
    try:
        print('\nPress ^C to abort domad creation')
        while not domad_uid :
            domad_uid = raw_input('specify a uid (shortname) for this domad:')
        if not domad_uid.endswith('/domad'):
            domad_uid = domad_uid + '/domad'
        domad_pw1 = False
        domad_pw2 = False
        while not domad_pwd:
            domad_pw1 = getpass('specify password for %s:' % domad_uid)
            domad_pw2 = getpass('retype password for %s:' % domad_uid)
            if domad_pw1 != domad_pw2:
                print('password mismatch. Try again.')
            elif len(domad_pw1) < 6:
                print('Passwords must have at least 6 chars. (well actualy all below 12 is considered insecure at the time of this writing)\n Try again.')
            else:
                domad_pwd = domad_pw1
        domad_fullname = raw_input("\nName and last name of the domain admin (default:%s): " % domad_fullname)
        
        print "Going to create Domain Administrator %s (%s) in %s." % (domad_uid, domad_fullname[2], domain_name)
        answer = ''
        while answer.lower() !='yes':
            answer = raw_input('Is this correct? (yes/no) :')
            if answer.lower() == 'no':
                return False
        if not authen.add_domad( domad_uid, domad_pwd ):
            print 'Error adding %s to KDC' % domad_uid
            return False
        if not db:
            return True
        domain_ID = db.get_itemID(domain_name)
        if not domain_ID:
            print 'No such Domain %s. But we added the domad to the authen backend already. Call a admin to fix this.' % domain_name
            return False
        if not db.add_domad(domain_ID, domad_uid[0], domad_pwd[1], domad_fullname[2]):
            print 'Error while adding %s to %s in the database backend. We already added him to the authen backend already. Call a admin to fix this.' % (domad_uid, domain_name)
            return False
        print "Do NOT FORGETT to add this user to the ACL's for the area where this domad has administrative rights !!\n"
        return True
    except Exception:
        #Just buck out. this usualy indicates a user abort. If its a bug, users will complain to admins or life in misery
        return False


if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] uid [domain]", description="""
add a new domad to domain. If no domain given, only add to KDC.
returns:
 0 on success
 1 if we had a problem add the new domad
 2 if bad parameters/options given
 3 if Instantiation of Objects failed
 4 bad credentials
""")
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account", default=False)
    parser.add_option("-v", action="store_true", dest="debug", help="be verbose", default=False)
    (options, args) = parser.parse_args()
    if len(args) <1 or len(args) > 2:
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
    
    if len(args) == 1:
        args[2] = ''
        db = False
    else:
        author = Classes.Author(config)
        if not author:
            sys.exit(3)
        db = author.authorize(userid.split('@')[0])
        if not db:
            sys.exit(4)
    if add_domad(authen, args[1], args[0], db):
        sys.exit(0)
    sys.exit(1)
