# coding: utf-8
import logging
import pickle

from UniDomain.functions import get_osrelease as get_osrelease


class udPolicyEngine(object):
    """
    the udPolicyEngine instantiates and runs the udPolicies.
    It ensures dependencies, loads Data from ldap and similar tasks.
    
    
    The policy engine will try instantiate policy plugins as listed below:
    udPolicy.<name>Policy_<dist>_<version>
    udPolicy.<name>Policy_<dist>
    udPolicy.<name>Policy_<system>
    udPolicy.<name>Policy
    This allows for distribution and even version specific plugins.
    """
    def __init__(self, policies, database, config):
        """data is a policy structure as returned by the attributeCollection class."""
        self.policies = {}
        self.config = config
        self.cache = []
        system, dist, release = get_osrelease()

        lastlen = len(policies) + 1
        todo = policies.keys()
        done = []

        while lastlen > len(todo):
            lastlen = len(todo)
            for policy in todo:
                # ldap doesnot preserve case, so we have to fix this here.
                if policy.endswith('policy'):
                    realpolicy='%sPolicy' % policy[0:-6]
                else:
                    realpolicy=policy
                try:
                    logging.debug('udPolicyEngine: instantiating udPolicy for %s (%s, %s)', realpolicy, dist, release)
                    try:
                        logging.debug('udPolicyEngine: trying UniDomain.udPolicy.%s_%s_%s', realpolicy, dist, release)
                        policy_module = __import__('UniDomain.udPolicy.%s_%s_%s' % (realpolicy, dist, release))
                        cls = getattr(getattr(policy_module.udPolicy, '%s_%s_%s' % (realpolicy, dist, release)), '%s'%(realpolicy))
                    except ImportError:
                        try:
                            logging.debug('udPolicyEngine: trying UniDomain.udPolicy.%s_%s', realpolicy, dist)
                            policy_module = __import__('UniDomain.udPolicy.%s_%s' % (realpolicy, dist))
                            cls = getattr(getattr(policy_module.udPolicy, '%s_%s' % (realpolicy, dist)), '%s'%(realpolicy))
                        except ImportError:
                            try:
                                logging.debug('udPolicyEngine: trying UniDomain.udPolicy.%s_%s', realpolicy, system)
                                policy_module = __import__('UniDomain.udPolicy.%s_%s' % (realpolicy, system))
                                cls = getattr(getattr(policy_module.udPolicy, '%s_%s' % (realpolicy, system)), '%s'%(realpolicy))
                            except ImportError:
                                try:
                                    logging.debug('udPolicyEngine: trying UniDomain.udPolicy.%s', realpolicy)
                                    policy_module = __import__('UniDomain.udPolicy.%s' % (realpolicy))
                                    cls = getattr(getattr(policy_module.udPolicy, '%s' % (realpolicy)), '%s'%(realpolicy))
                                except ImportError:
                                    logging.warning('udPolicyEngine: no plugin found for %s. Skipping.', realpolicy)
                                    todo.remove(policy)
                                    continue
                    if reduce(lambda f, x: f and (x in done), cls.load_requires, True):
                        self.policies[realpolicy] = cls(self, database, policies[realpolicy], config)
                        done.extend(cls.load_provides)
                        todo.remove(policy)
                    else:
                        logging.debug('delay instantiation due to not met requirements')
                except Exception, err:
                    logging.warning('udPolicyEngine: Can not load plugin for %s. %s', realpolicy, str(err))
                    raise
        if lastlen > 0:
            logging.warning('udPolicyEngine: Some policies could not been loaded due to not met requirements! (%s)', ','.join(todo))
        self.load_cache()
        
    def __del__(self):
        self.write_cache()
        
    def run(self):
        """ runs the engine, performing all required policies."""
        logging.debug('udPolicyEngine: Performing changes.')
        #we have to detect policy loops.
        #first we remove all unset policies:
        for policy in self.cache:
            if policy not in self.policies:
                logging.info('udPolicyEngine: removing policy %s', policy)
                # we can not call remove as we do not have a policy object anymore.
                # clean removal of policies should be done by empty-ing them first and remove them later.
        lastlen = len(self.policies) + 1
        todo = self.policies.keys()
        done = []
        
        while lastlen > len(todo):
            logging.debug('udPolicyEngine: looping with %i (was %i)', len(todo), lastlen)
            lastlen = len(todo)
            for policy in todo:
                # check if all requirements are met.
                logging.debug('checking %s, done=%s, req=%s', policy, done, self.policies[policy].requires)
                if reduce(lambda f, x: f and (x in done), self.policies[policy].requires, True):
                    if policy not in self.cache:
                        logging.info('udPolicyEngine: %s is new. running setup.', policy)
                        self.policies[policy].setup()
                        self.cache.append(policy)
                    logging.info('udPolicyEngine: updating %s.', policy)
                    self.policies[policy].update()
                    done.extend(self.policies[policy].provides)
                    todo.remove(policy)
                else:
                    logging.debug('udPolicyEngine: requirements for %s not met. delaying.', policy)
        if lastlen > 0:
            logging.warning('udPolicyEngine: Some policies could not been run due to not met requirements! (%s)', ','.join(todo))
            
        #We need force deletation of cache or we wont get written back. Not sure whats wrong.
        # but we still need a list of policy names.
        self.cache = self.policies.keys()
        self.policies = {}
                    
            
    def load_cache(self):
        """Load cache from file"""
        try:
            cachefile = open("%s/udPolicyEngine.cache" % (self.config.cachedir) , "r")
            self.cache = pickle.Unpickler(cachefile).load()
            cachefile.close()
            if 'keys' in self.cache:
                print 'bugged cache found. fixing.'
                self.cache = self.cache.keys()
        except Exception, err:
            #FIXME:read old cache file.
            #no cache file, we are a new hosts or someone deleted our cache.
            logging.info('udPolicyEngine: loading cache failed.')
            logging.debug(str(err))

    def write_cache(self):
        """write cache back to disk"""
        try:
            cachefile = open("%s/udPolicyEngine.cache" % (self.config.cachedir) , "w")
            pickle.Pickler(cachefile, pickle.HIGHEST_PROTOCOL).dump(self.cache)
            cachefile.close()
        except Exception, err:
            logging.warn('udPolicyEngine: saving cache failed:%s', str(err))
