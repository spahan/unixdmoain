# coding: utf-8
"""
Kerberos 5 Authentication Plugin for ud2 Client.
This is a abstract base class which defines some basic kerberos support.
For real authentication use the one of the submodules.

THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
FOR LICENCE DETAILS SEE share/LICENSE.TXT

(c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
(c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>
"""
import UniDomain.Classes
from UniDomain.functions import getlocalhostname
import tempfile
import subprocess
import os
import logging
import re

class Authen(UniDomain.Classes.Authen):
    """Basic Kerberos authentication class.
    This is a abstract base class for kerberos authentication.
    This class too defines some helpers to deal with Kerberos (eg kadmin etc).
    The authentication will be valid as long a instance object exists."""
    def __init__(self, config=None):
        """For security and encapsulation purposes, we create and use a own temporary ticket cache file.
        This cache file will be created as safe as possible. 
        After that we remove the file to ensure all tickets are destroyed even if kdestroy would fail.
        Again for Security, we determine the kerberos application path by searching for kdestroy. 
        This ensures we can at least destroy tickets."""
        if not config: config = UniDomain.Classes.Config()
        UniDomain.Classes.Authen.__init__(self, config)
        (self.krb5ccfs, self.krb5cc) = tempfile.mkstemp(prefix='krb5_ud2_', dir=config.cachedir)
        (self.krb5adminccfs, self.krb5admincc) = tempfile.mkstemp(prefix='krb5_ud2_', dir=config.cachedir)
        os.environ['KRB5CCNAME'] = 'FILE:%s' % self.krb5cc # required by gssapi
        self.kadm = False #set to kadmin arg list after proper initialization.
        self.env = {'LD_LIBRARY_PATH':'/usr/local/lib/'}
        self.keytab = None
        self.pw = None
    
    def __del__(self):
        """ make sure we close auth tokens properly """
        try: self.close()
        except: pass
        #try: UniDomain.Classes.Authen.__del__(self)
        #except: pass
    
    def close(self):
        """Close authentication.
        Destroy any credentials and deauth the user."""
        #using string for subprocess to force shell. Else redirection doesnt work and we get too much spam in output. We could use subprocess.Popen but im lazy.
        try: self.krb5ccfs.close()
        except: pass
        try: subprocess.call('%s -c "%s" 1>/dev/null 2>/dev/null' % (self.config.kdestroypath, self.krb5cc))
        except: pass
        try: os.remove(self.krb5cc) # should be unlinked by kdestroy. Try remove anyway in case of errors.
        except: pass
        try: self.krb5adminccfs.close()
        except: pass
        try: subprocess.call('%s -c "%s" 1>/dev/null 2>/dev/null' % (self.config.kdestroypath, self.krb5admincc))
        except: pass
        try: os.remove(self.krb5admincc)# should be unlinked by kdestroy. Try remove anyway in case of errors.
        except: pass
    
    def authenticate(self, **args):
        """
        @see UniDomain.Classes.Authen#authenticate
        """
        return false
    
    ### public methods required by base class ### 
      
    def get_service_name(self, service = 'host', host = getlocalhostname()):
        """
        @see UniDomain.Classes.Author#get_service_name
        """
        if '@' in service: service = service.split('@', 1)[0]
        if '/' in service: service, host = service.split('/', 1)
        return '%s/%s@%s' % (service, host, self.config.krb5realm)

    def add_service(self, service= 'host', host=getlocalhostname()):
        """
        @see UniDomain.Classes.Author#add_service
        """
        if not self.kadm: self.kadmin()
        logging.debug("add_service %s %s", service, host)
        if len(self.list_service(service, host)) > 0:
            logging.warning('Service %s %s already exists. Nothing changed.', service, host)
            return True
        service = self.get_service_name(service, host)
        logging.debug('%s will be added to KDC', service)
        sess = subprocess.Popen(self.kadm + ['-q', 'add_principal -policy service -pwexpire never -expire never -randkey %s' % (service)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, env=self.env)
        (sout, serr) = sess.communicate(None)
        if sout.find('Principal "%s" created.' % service) == -1:
            logging.error('%s %s not created in KDC.\nkadmin stderr:\n %s\nkadmin stdout:\n%s', service, host, serr, sout)
            return False
        return True 
        
    def delete_service(self, service= 'host', host= getlocalhostname()):
        """
        @see UniDomain.Classes.Author#delete_service
        """
        if not self.kadm: self.kadmin()
        logging.debug('delete_service_principal %s %s', service, host)
        if len(self.list_service(service, host)) == 0:
            logging.warning('%s does not exist in kerberos, nothing changed', host)
            return False
        service = self.get_service_name(service, host)
        logging.debug('%s will be removed from KDC.', service)
        sess = subprocess.Popen(self.kadm + ['-q', 'delete_principal -force ' + service], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        (sout, serr) = sess.communicate()
        if sout.find('Principal "%s" deleted.' % service) > -1:
            logging.info('%s deleted from KDC', service)
            return True
        logging.error('%s not deleted in KDC.\nkadmin stderr:\n %s\nkadmin stdout:\n%s', service, serr, sout)
        return False

    def list_service(self, service = 'host', host = getlocalhostname()):
        """
        @see UniDomain.Classes.Author#list_service
        """
        if not self.kadm: self.kadmin()
        service = self.get_service_name(service, host)
        logging.debug('canoncial servicename is %s', service)
        sess = subprocess.Popen(self.kadm + ['-q', 'listprincs ' + service], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        (sout, serr) = sess.communicate()
        logging.debug(sout)
        logging.debug(serr)
        return [x for x in sout.split('\n') if x==service]

    def get_service_keytab(self, service='host', host = getlocalhostname(), options="", keytab=None):
        """ get a keytab for service <service>/<fqdn>@<realm>"""
        if not self.kadm: self.kadmin()
        if not keytab: keytab = self.config.krb5keytab
        service = self.get_service_name(service, host)
        logging.debug('adding keytab for %s', service)
        sess = subprocess.Popen(self.kadm + ['-q', 'ktadd -k %s %s %s' % (keytab, options, service)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        (sout, serr) = sess.communicate()
        if serr == '\n\x07\x07\x07Administration credentials NOT DESTROYED.\n':
            logging.info('keytab for %s written to %s', service, keytab)
            logging.debug('removing old keys in keytab')
            sess = subprocess.Popen(self.kadm + ['-q', 'ktremove -k %s %s old' % (keytab, service)], env=self.env)
            sess.communicate()
            return True
        logging.error('Writing keytab for %s failed!\nkadmin stderr:\n %s\nkadmin stdout:\n%s', service, serr, sout)
        return False

    ### private kerb5 specfific funcs ###

def parse_name(stri):
    """parse cache location and principal name from klist output"""
    lines=stri.split('\n')
    if len(lines) < 1:
        logging.error('krb5_apache:Invalid ticket cache\n')
        return (False,False)
    cache = re.search(r'.*cache:\s+\w*:(.*)$', lines[0])
    princ = re.search(r'incipal:\s+(.*)$', lines[1])
    if cache and princ:
        return (cache.group(1), princ.group(1))

    logging.error('krb5_apache:Invalid ticket cache\n')
    return (False, False)
