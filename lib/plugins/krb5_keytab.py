# coding: utf-8
# THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
# FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
# (c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
# (c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
import UniDomain.plugins.krb5 as krb5
import os
import subprocess
import logging

from UniDomain.functions import getlocalhostname as hostname

class Authen(krb5.Authen):
    """
    Kerberos Authentication for ud2 client.
    This Class authenticates a user with a kerberos keytab file.
    Most values are taken from the config (if no username is passed in, we use the host-FQDN!)
    This will be used mainly for automatic login
    
    required configuration values:
        - krb5realm: realm to be used
        - krb5keytab: default keytab location
    """   
    def authenticate(self, **args):
        """
        authenticate a user using a keytab file
        @param keytab: the keytab location. If not set, we use the keytab specified in the config object.
        @type keytab: string
        @return: returns self or False
        """
        self.keytab = args.get('keytab', self.config.krb5keytab)
        self.user = args.get('user', 'host/%s' % hostname())
        if os.access(self.keytab, os.R_OK):
            sub = subprocess.call([self.config.kinitpath, '-c',self.krb5cc, '-k','-t',self.keytab, '-p',self.user])
            if sub == 0:
                sub = subprocess.Popen([self.config.klistpath, '-c', self.krb5cc], stdout = subprocess.PIPE)
                sout, serr = sub.communicate()
                logging.debug('krb5_keytab:krb5: %s', sout)
                logging.debug('krb5_keytab:krb5: %s', serr)
                (krb5cc, self.user) = krb5.parse_name(sout)
                if not (krb5cc and self.user):
                    logging.warning('krb5_keytab:Invalid keycache at %s', krb5cc)
                    return False
                if not krb5cc == self.krb5cc:
                    logging.warning('krb5_keytab: Using wrong keytab %s %s', krb5cc, self.krb5cc)
                self.user = self.user.split('@')[0]
                logging.debug( 'krb5_apache:Got krb5path from ticket: %s', self.krb5cc)
                logging.info( 'krb5_apache:Got principal from ticket: %s', self.user)
                self.is_authenticated = True
                return self
            logging.warning('Something went wrong while trying to kinit.')
        else:
            logging.error('Can not read from keytab file \'%s\'. Authentication failed.', self.keytab)
        return False

    def kadmin(self):
        """
        Initiate the kadmin interface.
        @return: self on success, False otherwise.
        """
        try:
            sub = subprocess.Popen([self.config.kinitpath, '-c', self.krb5admincc, '-k', '-t', self.keytab, '-S', 'kadmin/admin', self.user], stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            serr = sub.communicate()[1]
            if serr: 
                raise(Exception(serr))
            logging.debug('Successfully got kadmin ticket for %s', self.user)
            return self
        except Exception, err:
            logging.warning('Error while trying get admin credentials. Programm execution will continue, but we wont have any admin privileges in the authen backend\n' + str(err))
        return False
