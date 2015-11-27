# coding: utf-8
"""
Linux user policy implementation
"""
from UniDomain.udPolicy.userPolicy import userPolicy as base

import subprocess
import logging
import os

class  userPolicy(base):
    """
    This implementation uses the redhat useradd syntax.
    Debian based System use a slightly different and incompatible syntax and shall use the _debian implementation.
    """
    do_not_create_user_group_option = '-n' # -n is for redhat&co. debian&co use -N
    def addUser(self, user):
        try:
            # im not sure whos wrong, me or the manual. but i think the manual states this istn required....but it is.
            r = subprocess.call(['mkdir', '-p', user['homeDirectory'].rsplit('/', 1)[0]])
            r = subprocess.call([
                'useradd',
                '-c%s' % user['gecos'],
                '-d%s' % user['homeDirectory'], '-m', #create homedir if not exists.
                '-g%s' % user['gidNumber'], self.do_not_create_user_group_option, #do not create user group
                #'-p"*K*"', # as suggested by http://www.debian-administration.org/articles/570#PAM_configuration
                '-s%s' % user['loginShell'],
                '-u%s' % user['uidNumber'],
                user['uid']], stdout=open(os.devnull, 'w'))
            if r == 0:
                return True
            logging.warning('userPolicy_Linux: failed to add %s. useradd returned %i', user['uid'], r)
        except Exception, err:
            logging.error('userPolicy_Linux: failed to add %s. %s', user['uid'], str(err))
        return False
        
    def removeUser(self, user):
        try:
            if subprocess.call(['userdel', user], stdout=open(os.devnull, 'w')) != 0:
                logging.warning('userPolicy_Linux: failed to delete %s.', user)
                return True
        except Exception, err:
            logging.error('userPolicy_Linux: failed to delete %s. %s', user, str(err))
        return False
        
    def updateUser(self, user):
        try:
            # check if settings are right before change them. else we spam the audit log
            mod = ['usermod']
            #r = subprocess.call(['grep', '%s:"*K*"' % user['uid'], '/etc/shadow'], stdout=open(os.devnull, 'w'))
            #if r != 0:
            #    mod.append('-p"*K*"')
            r = subprocess.call(['grep', '%s:x:%s:.*:%s:' % (user['uid'], user['uidNumber'], user['homeDirectory']), '/etc/passwd'], stdout=open(os.devnull, 'w'))
            if r != 0:
                mod.append('-d%s' % user['homeDirectory'])
                mod.append('-u %s' % user['uidNumber'])
            if len(mod) > 1:
                mod.append(user['uid'])
                r = subprocess.call(mod, stdout=open(os.devnull, 'w'))
                if r == 0:
                    pass
                if r == 4:
                    logging.info('userPolicy_Linux: failed to update %s. user does not exist (4). Adding...', user['uid'])
                    if not(self.addUser(user)):
                        return False
                elif r == 6:
                    logging.info('userPolicy_Linux: failed to update %s. user does not exist (6). Adding...', user['uid'])
                    if not(self.addUser(user)):
                        return False
                else:
                    logging.warning('userPolicy_Linux: failed to update %s. usermod returned %i', user['uid'], r)
                    #shall be a cfengine policy if want fix permissions.
                    #self.fixHomeDirPermission(user)
            else:
                logging.info('userPolicy_Linux: nothing to do for %s', user['uid'])
            logging.info('cecking homedir for %s', user['uid'])
            if not(os.path.exists(user['homeDirectory'])):
                try:
                    self.makeHomeDir(user)
                except Exception, err:
                    logging.warning('trouble create Homedir for %s (%s)', user['uid'], err)
                    return False
            return True
        except Exception, err:
            logging.error('userPolicy_Linux: failed to update %s. %s', user['uid'], str(err))
        return False


