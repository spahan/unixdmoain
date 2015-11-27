# coding: utf-8
"""
Free BSD implementation for userPolicy.

"""
from UniDomain.udPolicy.userPolicy import userPolicy as base

import subprocess
import logging
import os

class  userPolicy(base):
    def addUser(self, user):
        try:
            sub = subprocess.Popen([
                'pw','useradd',
                user['uid'],
                '-c%s' % user['gecos'],
                '-d%s' % user['homeDirectory'], '-m', #create homedir if not exists.
                '-g%s' % user['gidNumber'], 
                '-H0', #read password (x) from stdin. we cant just set it to x as th epw util does not allow this.
                '-s/usr/local%s' % user['loginShell'], #bash not in /bin/bash on freebsd.
                '-u%s' % user['uidNumber']], stdout=open(os.devnull, 'w'), stdin=subprocess.PIPE)
            sub.communicate('*K*')
            if sub.returncode == 0:
                return True
            logging.warning('userPolicy_FreeBSD: failed to add %s. useradd returned %i', user['uid'], sub.returncode)
        except Exception, err:
            logging.error('userPolicy_FreeBSD: failed to add %s. %s', user['uid'], str(err))
        return False
        
    def removeUser(self, user):
        try:
            if subprocess.call(['pw', 'userdel', user], stdout=open(os.devnull, 'w')) == 0:
                return True
            logging.warning('userPolicy_FreeBSD: failed to delete %s.', user)
        except Exception, err:
            logging.error('userPolicy_FreeBSD: failed to delete %s. %s', user, str(err))
        return False
        
    def updateUser(self, user):
        try:
            r = subprocess.call(['pw', 'usermod', user['uid'], '-u', user['uidNumber']], stdout=open(os.devnull, 'w'))
            if r == 0:
                pass
            elif r == 67:
                logging.info('userPolicy_FreeBSD: failed to update %s. user does not exist (67). Adding...', user['uid'])
                if not(self.addUser(user)):
                    return False
            else:
                logging.warning('userPolicy_FreeBSD: failed to update %s. usermod returned %i', user['uid'])
            logging.debug('userPolicy_FreeBSD: checking homedir for %s', user['uid'])
            if not(os.path.exists(user['homeDirectory'])):
                try:
                    self.makeHomeDir(user)
                except Exception, err:
                    logging.warning('trouble create Homedir for %s (%s)', user['uid'], err)
                    return False
            return True
        except Exception, err:
            logging.error('userPolicy_FreeBsd: failed to update %s. %s', user['uid'], str(err))
        return False
