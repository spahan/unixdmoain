# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
import UniDomain.Classes
import subprocess
import os
import logging
import UniDomain.plugins.krb5 as krb5

#we can not use the base krb5 class as that sets up root-only stuff.
class Authen(krb5.Authen):
    """
    Kerberos Authentication Plugin for ud2 client.
    This class uses credentials provided by a third party (eg, a ticket cache file).
    
    Does not support any kadmin usage since we have no such ticket.
    B{Consider this a security feature instead a limitation}
    
    WARNING: As this class does not create the ticket cache, we do B{not} destroy it.
    The cache providing application is responsible for delete the cache!
    """
    def __init__(self, config=False):
        if not config: 
            config = UniDomain.Classes.Config(True)
        krb5.Authen.__init__(self, config)
        krb5.Authen.close(self)
        self.kadm = False #This authentication class does NOT support kadmin usage.
        self.krb5cc = False
    def __del__(self):
        """We got ticket from outside, we let outside deal with cleanup"""
        pass

    def authenticate(self, **args):
        """user authen is already done by third party.
        This will extract the kerberos principal and data in the ticket file.
        without arguments we get the ticket provided by the environment.
        @param ccpath: path to the kerberos ticket cache. may be prefixed with 'FILE:' for compatibility reason. If not specified, we use KRB5CCNAME environment variable.
        @type ccpath: string
        @return: returns the I{Full qualified user name}. This includes the kerberos realm!
        """
        try:
            self.krb5cc = args.pop('ccpath')
            if self.krb5cc.find(':') > 0:
                self.krb5cc = self.krb5cc.split(':')[1]
            sub = subprocess.Popen([self.config.klistpath, '-c', self.krb5cc], stdout = subprocess.PIPE)
        except KeyError:
            sub = subprocess.Popen([self.config.klistpath], stdout = subprocess.PIPE)
        sout, serr = sub.communicate()
        logging.debug('krb5_apache:krb5: %s', sout)
        logging.debug('krb5_apache:krb5: %s', serr)
        (self.krb5cc, self.user) = krb5.parse_name(sout)
        if not (self.krb5cc and self.user): 
            return False
        self.user = self.user.split('@')[0]
        logging.info( 'krb5_apache:Got krb5path from ticket: %s', self.krb5cc)
        logging.info( 'krb5_apache:Got principal from ticket: %s', self.user)
        os.environ['KRB5CCNAME'] = self.krb5cc
        self.is_authenticated = True
        return self

