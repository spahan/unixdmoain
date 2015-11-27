# coding: utf-8
"""
this udPolicy wraps a cf engine policy
"""

import UniDomain.udPolicy.udPolicy as udPolicy
import shutil
import logging
import os
import subprocess
import re

def detect_cfengine():
    """ detect which cfengine version is installed. """
    fnull = open(os.devnull, 'w')
    rval = 0
    if subprocess.call(['ls', '/var/cfengine/bin/cfagent'], stdout=fnull, stderr=fnull) == 0:
        rval = 2
    if subprocess.call(['ls', '/var/cfengine/bin/cf-agent'], stdout=fnull, stderr=fnull) == 0:
        rval = 3
    fnull.close()
    return rval

class cfPolicy(udPolicy.udPolicy):
    """ just a wrapper for a cfengine policy."""
    def __init__(self, engine, db, data, config):
        udPolicy.udPolicy.__init__(self, engine, db, data, config)
        self.policies = data['policyClass']
        # add the managed domain as a class.
        domain_id = re.search("ou=([^,]*),%s" % (config.ldapbase), db.get_domainID())
        if domain_id:
            self.policies.add( domain_id.group(1).replace('.','_'))
        else:
            logging.warning("cfPolicy: ud domain name not found! please check your config")
        self.cfe_version = detect_cfengine()
        logging.debug('cfPolicy: cfengine version %i detected', self.cfe_version)
        
    def update(self):
        print 'policy classes for this host set by UniDomain:\n---------------------------------------------'
        print '\n'.join([name for name in self.policies])
        print '---------------------------------------------\n'
        if self.cfe_version == 3:
            try:
                policy_file = open(self.config.policyfile, 'w')
                policy_file.write('\n'.join(self.policies))
                policy_file.close()
            except Exception, err:
                logging.warning('cfPolicy: can not set cfengine managed policies in %s', self.config.policyfile)
        if self.cfe_version == 2:
            try:
                shutil.rmtree(self.config.policydir)
            except Exception, err:
                logging.debug('cfPolicy: can not remove cf engine policy directory at %s. %s Ignoring.', self.config.policydir, str(err))
            try:
                os.mkdir(self.config.policydir, 0755)
            except Exception, err:
                logging.warning('cfPolicy: can not create cf engine policy directory at %s.', self.config.policydir)
                logging.debug(str(err))
            for name in self.policies:
                try:
                    logging.debug('cfPolicy: adding cf engine policy %s', name)
                    f = open('%s/%s' % (self.config.policydir, name), 'w')
                    f.write("this file is automatic maintained by the UniDomain, all write is useless ..")
                    f.close()
                except Exception, err:
                    logging.warning('cfPolicy: Can not add cfengine policy %s.', name)
                    logging.debug(str(err)) 
    def remove(self):
        if self.cfe_version == 3:
            try:
                os.remove(self.config.policyfile)
            except Exception, err:
                logging.warning('cfPolicy: Failed to remove managed_classes at %s (%s)', self.config.policyfile, err)
        if self.cfe_version == 2:
            try:
                shutil.rmtree(self.config.policydir)
            except Exception, err:
                logging.warning('cfPolicy: can not remove cfenigne policy directory at %s.', self.config.policydif)
