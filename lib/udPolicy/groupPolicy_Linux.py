# coding: utf-8
"""
red hat group policy implementation
"""
from UniDomain.udPolicy.groupPolicy import groupPolicy as base
from UniDomain.udPolicy.groupPolicy import ugsyncPolicy as sync_base

import subprocess
import logging
import os

class  groupPolicy(base):
    """group Policy implementation for Linux"""
    def addGroup(self, group):
        try:
            if subprocess.call(['groupadd', '-g', group['gidNumber'], group['cn']], stdout=open(os.devnull, 'w')) > 0:
                logging.error('groupPolicy_linux: failed to add %s.', group['cn'])
        except Exception, err:
            logging.error('grouPolicy_linux: failed to add %s. %s', group['cn'], str(err))
        
    def removeGroup(self, group):
        try:
            if subprocess.call(['groupdel', group]) > 0:
                logging.error('grouPolicy_linux: failed to delete %s.', group)
                # this mostly happens ifthis is a users primary group and we want remove the user.
                # just push back the ggroup into the cache and let the system delete it next time.
                self.data['unixGroup'].add(group)
        except Exception, err:
            logging.error('grouPolicy_linux: failed to delete %s. %s', group, str(err))
        
    def updateGroup(self, group):
        try:
            r = subprocess.call(['groupmod', '-g', group['gidNumber'], group['cn']], stdout=open(os.devnull, 'w'))
            if r > 0:
                if r == 4:
                    logging.info('groupPolicy_linux: failed to update %s. group doesn’t exist (4). Adding...', group['cn'])
                    self.addGroup(group)
                elif r == 6:
                    logging.info('groupPolicy_linux: failed to update %s. group doesn’t exist (6). Adding...', group['cn'])
                    self.addGroup(group)
                else:
                    logging.error('groupPolicy_linux: failed to update %s. groupmod returned %i', group['cn'], r )
                return
        except Exception, err:
            logging.error('grouPolicy_linux: failed to update %s. %s', group['cn'], str(err))
            
    def getSyncPolicy(self, data):
        return ugsyncPolicy(self.engine, self.db, data, self.config)
            
class ugsyncPolicy(sync_base):
    def update(self):
        for user in self.data:
            try:
                logging.debug('ugsyncPolicy (Linux), usermod: %r', ['usermod', '-G', ','.join(self.data[user]), user])
                r = subprocess.call(['usermod', '-G', ','.join(self.data[user]), user], stdout=open(os.devnull, 'w'), stderr=subprocess.STDOUT)
                if r == 0:
                    continue
                elif r == 6:
                    #user not on system. ignore
                    continue
                elif r == 0:
                    #user logged in. try next time.
                    continue
                logging.warning('groupPolicy_linux: ugsyncPolicy: failed to synch groups for %s', user)
            except Exception, err:
                logging.error('groupPolicy_linux: ugsyncPolicy: failed to synch groups for %s (%s)', user, str(err))
