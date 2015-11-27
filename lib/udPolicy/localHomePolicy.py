# coding: utf-8
"""
This policy manages posixGroups.

Some caveats:
Some operations require 2 runs of the engine to completly sync (namely when dealing with adding users by group and similar).
"""

import UniDomain.udPolicy.udPolicy as udPolicy
import os
import os.path
import logging

class localHomePolicy(udPolicy.udPolicy):
    """
    The localHome policy provides local home dirs for users instead AFS/NFS.
    One can exclude specific users from local homedirs using the 'disabled' attribute
    """
    provides = ['localHomePolicy']
    load_provides = ['localHomePolicy']
    load_requires = ['userPolicy'] #need pull in primary groups from user policy.
        
    def __init__(self, engine, db, data, config):
        """groupPolicies can have a single attribute list named 'gid' containing the hosts group names."""
        udPolicy.udPolicy.__init__(self, engine, db, data, config)
        # until this is stable, we use the custom attribute.
        try:
            homeDir = data['customPolicyData'].pop()
            if homeDir.startswith('/'):
                disabled = data.get('disabledPolicyData', [])
                #create base homedir:
                if not os.path.exists(homeDir):
                    logging.info('localHomePolicy: %s does not exist. creating.', homeDir)
                    os.makedirs(homeDir, 0755)
                if not os.path.isdir(homeDir):
                    logging.error('localHomePolicy: %s is not a directory. can not proceed!', homeDir)
                else:
                    for user in engine.policies['userPolicy'].userData:
                        if not user in disabled:
                            engine.policies['userPolicy'].userData[user]['homeDirectory'] = "%s/%s" % (homeDir, user)
                            logging.info('localHomePolicy: using %s as homedir for %s', homeDir, user)
                        else:
                            logging.debug('localHomePolicy: skipping %s as is disabled', user)
            else:
                logging.warning('localHomePolicy: invalid local homedir %s. Needs start with /', homeDir)
        except:
            #no local home policy configured.
            pass
