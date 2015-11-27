# coding: utf-8
"""
This policy manages sudoers
We use the standart group 'wheel' on redhat/freebsd

"""

import UniDomain.udPolicy.udPolicy as udPolicy
import logging

class sudoPolicy(udPolicy.cachedUdPolicy):
    """
    The sudo Policy adds user to the sudoers file.
    """

    #which group has sudo admin rights.
    sudo_group = 'wheel'

    # This policy provides the '' policy.
    provides = ['sudoPolicy']
    load_requires = ['groupPolicy']
    load_provides = ['sudoPolicy']

    def __init__(self, engine, db, data, config):
        """sudo Policies contain:
            - uid : list of user ids
            - unixGroup : users from this list will be added.
            - disable : this users will not be added (usefull for group/host-specific removal)"""
        udPolicy.cachedUdPolicy.__init__(self, engine, db, data, config, "sudoPolicy")
        #NOTE: if we allow to add groups to this policy, we need cache all users in a single list.
        # We need edit the cache value after destroy
        users = self.data.get('uid', set())
        groups = db.get_group_data(self.data.get('unixGroup', set()))
        logging.debug('sudoPolicy: adding unix groups %r', groups)
        for group in groups:
            for uid in group.get('memberUid', set()):
                users.add(uid)
        disabled = self.data.get('disabledPolicyData', set())
        
        self.userData = {}
        for user in db.get_user_data(users):
            if not user['uid'] in disabled:
                self.userData[user['uid']] = user
                if user['uid'] in engine.policies['groupSyncHelper'].data:
                    engine.policies['groupSyncHelper'].data[user['uid']].append(self.sudo_group)
                else:
                    logging.info('sudoPolicy: %s not configured here. skipping', user['uid'])
            else:
                logging.info('%s is disabled', user['uid'])
        
    def update(self):
        print 'sudoers set for this host by UniDomain:\n---------------------------------------------'
        print ', '.join(self.userData)
        print '---------------------------------------------\n'

