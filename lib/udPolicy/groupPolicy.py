# coding: utf-8
"""
This policy manages posixGroups.

Some caveats:
Some operations require 2 runs of the engine to completly sync (namely when dealing with adding users by group and similar).
"""

import UniDomain.udPolicy.udPolicy as udPolicy
import logging

class groupPolicy(udPolicy.cachedUdPolicy):
    """
    The groupPolicy manages groups on the host.
    
    The policy Data Dictionary may contain:
        'unixGroup' : a list of group names to add to the system.

    The group policy will pull in all users primary groups.
    This requires us to have the load dependency to the userPolicy.
    
    The group Policy will additionaly install a post-policy to synchronize all users with their groups.
    This post-policy require the users to be present, eg a run dependency for 'user'
    This too will only add users to groups which are present on the system.

    """
    # This policy provides the 'group' policy.
    provides = ['groupPolicy']
    load_provides = ['groupPolicy']
    load_requires = ['userPolicy'] #need pull in primary groups from user policy.
        
    def __init__(self, engine, db, data, config):
        """groupPolicies can have a single attribute list named 'unixGroup' containing the hosts group names."""
        udPolicy.cachedUdPolicy.__init__(self, engine, db, data, config, "groupPolicy")
        #----
        #get groups for this host from db.
        #----
        groups = db.get_group_data(self.data['unixGroup'])

        self.groupData = {}
        for g in groups:
            self.groupData[g['cn']] = g
        self.groupNums = {}
        for group in self.groupData:
            self.groupNums[self.groupData[group]['gidNumber']] = group

        # pull in primary groups
        groupIDs = set([engine.policies['userPolicy'].userData[user]['gidNumber'] for user in engine.policies['userPolicy'].userData])
        # only ask for groups not already here.
        groups = db.get_group_data_by_id(groupIDs - set(self.groupNums.keys()))
        self.data['unixGroup'] |= set([g['cn'] for g in groups]) #required for cache. or we try add the group each time we update.
        logging.debug('groupPolicy: adding primary groups: %s', groups)
        for primGroup in groups:
            self.groupData[primGroup['cn']] = primGroup
            self.groupNums[primGroup['gidNumber']] = primGroup['cn']
        
        #we need have groups on the system BEFORE we add/change users.
        #but we need add users before we can add them to groups.
        #therefore we insert a sync policy into the engine which depends on user and group policy and does the work.
        userData = {} # we need a user->group mapping in addition to group->user mapping.
        for group in self.groupData:
            if self.groupData[group]['memberUid']:
                for uid in self.groupData[group]['memberUid']:
                    if uid not in userData:
                        userData[uid] = []
                    userData[uid].append(self.groupData[group]['cn'])
            else:
                logging.debug('no user data for group %s, scanning users',  self.groupData[group])
                for uid in engine.policies['userPolicy'].userData:
                    if engine.policies['userPolicy'].userData[uid]['gidNumber'] == self.groupData[group]['gidNumber']:
                        logging.debug(' %s is in group %s', engine.policies['userPolicy'].userData[uid]['uid'], self.groupData[group]['cn'])
                        if uid not in userData:
                            userData[uid] = []
                        userData[uid].append(self.groupData[group]['cn'])
        logging.debug('data is %r' , userData)
        # we need pull in local group defs
        groupfile = open('/etc/group','r')
        for groupline in groupfile:
            if groupline.startswith('#'): continue
            gpl = groupline.split(':')
            gpu = gpl[3].strip().split(',')
            if gpl[0] != 'wheel' and gpl[0] not in self.groupData.keys() and gpl[0] not in self.groupData.keys():
                logging.debug('group %s is local!? scanning for users', gpl[0])
                for user in userData.keys():
                    if user in gpu:
                        logging.debug('user %s is in local group %s. adding to %s', user, gpl[0], userData[user])
                        userData[user].append(gpl[0])
        groupfile.close()

        logging.debug('groupPolicy: adding sync helper with:%s', ','.join(['%s:%s' % (u, ','.join(userData[u])) for u in userData]))
        self.engine.policies['groupSyncHelper'] = self.getSyncPolicy(userData)
    
    def update(self):
        print 'group entries for this host set by UniDomain:\n---------------------------------------------'
        print '\n'.join(['%s:x:%s:%s' %(self.groupData[g]['cn'], self.groupData[g]['gidNumber'], ','.join(self.groupData[g]['memberUid'])) for g in self.groupData])
        print '---------------------------------------------\n'

        #newGroups = map(lambda x: x['cn'], self.groupData)
        oldGroups = self.cache.get('unixGroup', set())
        for group in oldGroups:
            if group not in self.groupData:
                logging.info('groupPolicy: removing %s', group)
                self.removeGroup(group)
        for group in self.groupData:
            if self.groupData[group]['cn'] not in oldGroups:
                logging.info('groupPolicy: adding %s', group)
                self.addGroup(self.groupData[group])
            logging.info('groupPolicy: updating %s', group)
            self.updateGroup(self.groupData[group])
        
    def addGroup(self, group):
        """add group to system"""
        #implement this in a distribution specific way.
        logging.debug('ADD GROUP: %s', group)

    def removeGroup(self, group):
        """remove group from system"""
        logging.debug('REMOVE GROUP: %s', group)
        #implement this in a distribution specific way.

    def updateGroup(self, group):
        """update groups with group->user mapping"""
        logging.debug('UPDATE GROUP: %s', group)
        #implement this in a distribution specific way.

    def getSyncPolicy(self, data):
        """Must return a ugsyncPolicy implementation."""
        return ugsyncPolicy(self.engine, self.db, data, self.config)
        
class ugsyncPolicy(udPolicy.udPolicy):
    """This is a helper policy to sync users and groups.
    This policy will be run after the users have been updated."""
    requires = ['groupPolicy','userPolicy']
    provides = ['groupSyncHelper']
