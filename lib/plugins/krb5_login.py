# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
# 
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
Kerberos Authentication for ud2 client.
This class will ask for credentials from the user B{interactively}
Usaly used for human accounts (domad/admin)

required configuration values:
    - krb5realm: realm to be used
"""
import UniDomain.plugins.krb5 as krb5
from getpass import getpass
import subprocess
import logging

class Authen(krb5.Authen):
    """
    Kerberos Authentication for ud2 client.
    This class will ask for credentials from the user B{interactively}
    Usaly used for human accounts (domad/admin)
    
    required configuration values:
        - krb5realm: realm to be used
    """
    def authenticate(self, **args):
        """
        authenticate user.
        Will ask for password B{interactively}.
        If no Username is passed in, we will ask for that too.
        @param user: if set, the login name to authenticate. if not set, this function asks interactively for a username
        @type user: string
        @param password: if set, the password for this user. if not set, this function asks interactively for a password 
        @type password: string
        @return: returns self on success, False otherwise
        """
        self.user = args.get('user', False)
        if not self.user:
            print "\nWelcome to the UnixDomain"
            print "============================="
            try:
                while not self.user: 
                    self.user = raw_input('account name : ')
            except KeyboardInterrupt:
                return False
        self.pw = args.get('pw', '') # ONLY use this for testing!!!
        while not self.pw : 
            self.pw = getpass('password : ')
        sub = subprocess.Popen([self.config.kinitpath, '-c', self.krb5cc, '%s@%s' %(self.user, self.config.krb5realm)], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        (sout, serr) = sub.communicate(self.pw + '\n')
        sub = subprocess.Popen([self.config.klistpath, '-c', self.krb5cc], stdout=subprocess.PIPE)
        (sout, serr) = sub.communicate()
        logging.debug('krb5_keytab:krb5: %s', sout)
        logging.debug('krb5_keytab:krb5: %s', serr)
        (self.krb5cc, self.user) =  krb5.parse_name(sout)
        if not (self.krb5cc and self.user):
            logging.warning('krb5_keytab:Invalid keycache at %s', self.krb5cc)
            return False
        self.user = self.user.split('@')[0]
        self.is_authenticated = True
        return self

    def kadmin(self):
        """
        Initiate the kadmin interface.
        @return: self on success, False otherwise.
        """
        try:
            sub = subprocess.Popen([self.config.kinitpath, '-c', self.krb5admincc, '-S', 'kadmin/admin', '%s@%s' %(self.user, self.config.krb5realm)], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            (sout, serr) = sub.communicate(self.pw + '\n')
            sub = subprocess.Popen([self.config.klistpath, '-c', self.krb5admincc], stdout=subprocess.PIPE)
            sout, serr = sub.communicate()
            logging.debug('krb5_keytab:krb5: %s', sout)
            logging.debug('krb5_keytab:krb5: %s', serr)
            (self.krb5admincc, user) =  krb5.parse_name(sout)
            if not (self.krb5cc and user):
                raise(str(serr))
            logging.debug('Successfully got kadmin ticket for %s\n', user)
            self.kadm = [self.config.kadminpath, '-c', self.krb5admincc]
            return self
        except Exception, err:
            logging.warning('Error while trying get admin credentials. Programm execution will continue, but we wont have any admin privileges in the authen backend\n' + str(err))
        return False

