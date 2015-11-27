# coding: utf-8
"""
This policy manages posixUsers.
"""

import UniDomain.udPolicy.udPolicy as udPolicy
import logging
import os
import os.path
import shutil

class userPolicy(udPolicy.cachedUdPolicy):
    """
    The userPolicy manages users on the host.
    
    The policy Data Dictionary may contain:
            - uid : list of user ids
            - unixGroup : users from this list will be added.
            - disable : this users will not be added (usefull for group/host-specific removal)

    """
    provides = ['userPolicy']
    requires = ['groupPolicy']
    load_provides = ['userPolicy']
        
    def __init__(self, engine, db, data, config):
        """user Policies contain:
            - uid : list of user ids
            - unixGroup : users from this list will be added.
            - disable : this users will not be added (usefull for group/host-specific removal)"""
        udPolicy.cachedUdPolicy.__init__(self, engine, db, data, config, "userPolicy")
        #NOTE: if we allow to add groups to this policy, we need cache all users in a single list.
        # We need edit the cache value after destroy
        users = self.data.get('uid', set())
        groups = db.get_group_data(self.data.get('unixGroup', set()))
        logging.debug('userPolicy: adding unix groups %r', groups)
        for group in groups:
            for uid in group.get('memberUid', set()):
                users.add(uid)
        disabled = self.data.get('disabledPolicyData', set())
        
        self.userData = {}
        for user in db.get_user_data(users):
            if not user['uid'] in disabled:
                self.userData[user['uid']] = user
            else:
                logging.info('%s is disabled', user['uid'])

    def update(self):
        print 'passwd entries for this host set by UniDomain:\n---------------------------------------------'
        print '\n'.join(['%(uid)s:x:%(uidNumber)s:%(gidNumber)s:%(gecos)s:%(homeDirectory)s' % self.userData[u] for u in self.userData])
        print '---------------------------------------------\n'

        for user in self.cache:
            if user not in self.userData:
                logging.info('userPolicy: removing %s', user)
                self.removeUser(user)
        for user in self.userData:
            if self.userData[user]['uid'] not in self.cache:
                logging.info('userPolicy: adding %s', user)
                self.addUser(self.userData[user])
            logging.info('userPolicy: updating %s', user)
            self.updateUser(self.userData[user])
        # cache userData
        self.data = self.userData
                    
    def addUser(self, user):
        """call add user"""
        #implement this in a distribution specific way.
        logging.debug('ADD USER: %s', user)
        return False
    def removeUser(self, user):
        """call remove user"""
        #implement this in a distribution specific way.
        logging.debug('REMOVE USER: %s', user)
        return False
    def updateUser(self, user):
        """call upate user"""
        #implement this in a distribution specific way.
        logging.debug('UPDATE USER: %s', user)
        return False

    #Helpers to create homedir on user update.
    def makeHomeDir(self, user):
        """create homedirs if not exist"""
        logging.info('creating home directory for %s at %s', user['uid'], user['homeDirectory'])
        basedir = os.path.dirname(user['homeDirectory'].rstrip('/'))
        while basedir:
            os.system("mkdir -p %s" % basedir)
            os.chmod(basedir, 0755)
            basedir = os.path.dirname(basedir.rstrip('/'))
        if os.path.exists(user['homeDirectory']):
            logging.info('userPolicy: makeHomeDir: home dir exists for %s', user['uid'])
        else:
            logging.info('userPolicy: makeHomeDir: creating home dir for %s' , user['uid'])
            shutil.copytree('/etc/skel', user['homeDirectory'])
            self.fixHomeDirPermission(user)

    def fixHomeDirPermission(self, user):
        """ quick and dirty fix homedir permissions. shoudl be done by cfengine actualy"""
        logging.info("checking home directory permissions for %s at %s", user['uid'], user['homeDirectory'])
        os.chown(user['homeDirectory'], int(user['uidNumber']), int(user['gidNumber']))
        os.chmod(user['homeDirectory'], 0700)
        for base, dirs, files in os.walk(user['homeDirectory']):
            for idir in dirs:
                os.chown(os.path.join(base, idir), int(user['uidNumber']), int(user['gidNumber']))
                os.chmod(os.path.join(base, idir), 0700)
            for ifile in files:
                os.chown(os.path.join(base, ifile), int(user['uidNumber']), int(user['gidNumber']))
                os.chmod(os.path.join(base, ifile), 0600)
