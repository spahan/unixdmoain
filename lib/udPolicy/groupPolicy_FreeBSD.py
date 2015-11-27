# coding: utf-8
"""
group Policy for FreeBSD (8)
"""
from UniDomain.udPolicy.groupPolicy import groupPolicy as base
from UniDomain.udPolicy.groupPolicy import ugsyncPolicy as sync_base

import subprocess
import logging
import os

class  groupPolicy(base):
    def addGroup(self, group):
        try:
            if subprocess.call(['pw', 'groupadd', group['cn'], '-g', group['gidNumber']], stdout=open(os.devnull, 'w')) > 0:
                logging.error('groupPolicy_FreeBSD: failed to add %s.', group['cn'])
        except Exception, err:
            logging.error('grouPolicy_FreeBSD: failed to add %s. %s', group['cn'], str(err))
        
    def removeGroup(self, group):
        try:
            if subprocess.call(['pw', 'groupdel', group]) > 0:
                logging.error('grouPolicy_FreeBSD: failed to delete %s.', group)
                # this mostly happens ifthis is a users primary group and we want remove the user.
                # just push back the ggroup into the cache and let the system delete it next time.
                self.data['unixGroup'].add(group)
        except Exception, err:
            logging.error('grouPolicy_FreeBSD: failed to delete %s. %s', group, str(err))
        
    def updateGroup(self, group):
        try:
            r = subprocess.call(['pw', 'groupmod', group['cn'], '-g', group['gidNumber']], stdout=open(os.devnull, 'w'))
            if r > 0:
                if r == 65:
                    logging.info('groupPolicy_FreeBSD: failed to update %s. group may not exist (67). Try adding...', group['cn'])
                    self.addGroup(group)
                else:
                    logging.error('groupPolicy_FreeBSD: failed to update %s. pw returned %i', group['cn'], r )
                return
        except Exception, err:
            logging.error('grouPolicy_FreeBSD: failed to update %s. %s', group['cn'], str(err))
            
    def getSyncPolicy(self, data):
        return ugsyncPolicy(self.engine, self.db, data, self.config)
            
class ugsyncPolicy(sync_base):
    def update(self):
        for user in self.data:
            try:
                r = subprocess.call(['pw', 'usermod', '-G', ','.join(self.data[user]), '-n', user], stdout=open(os.devnull, 'w'))
                if r == 0:
                    continue
                elif r == 67:
                    #user not on system. ignore
                    continue
                logging.warning('groupPolicy_FreeBSD: ugsyncPolicy: failed to synch groups for %s', user)
            except Exception, err:
                logging.error('groupPolicy_FreeBSD: ugsyncPolicy: failed to synch groups for %s (%s)', user, str(err))
