# coding: utf-8

import logging
import pickle

class udPolicy(object):
    """
    base class for all udPolicy Objects
    
    udPolicies should have a "provides" and a "requires" attributes.
    the "provides" attribute usualy is the policy name without the -Policy suffix.
    "abstract Policies" should not set a provides attribute.
    the "requires" attribute lists the "provides" required to run this policy.
    If "requires" is not empty, the run of the policy is delayed until the required policies have been run.

    udPolicies have a "load_requires" attributes.
    as the "require" attribute, this allows to define the load sequence of the policy plugins.

    Example:
    A common requirement is the 'user' policy, to modify the user settings.
    The 'group' Policy requires the users to be loaded so it can pull the primary user groups.
    The user Policyusualy requires the users groups to be present on the system, and tehrefore requires
    to run after the 'group' policy.
    
    A warnign about the setup/remove methodes:
    The UniDomain System TRIES to detect if a policy has been newly installed or removed from the system.
    However, this only works reliable if the cache is set up correct.
    
    """
    provides = []
    requires = []

    load_provides = []
    load_requires = []
    
    def __init__(self, engine, db, data, config):
        self.config = config
        self.data = data
        self.db = db
        self.engine = engine
    def setup(self):
        """called if we THINK based on existence of a cache entry) we have been newly set.
        after setup a call to update() is made."""
        pass
    def update(self):
        """called each time we are run and the policy is already present on the host."""
        pass
    def remove(self):
        """called if the policy is removed from the host"""
        
class cachedUdPolicy(udPolicy):
    """a udPolicy which uses a dictionary-cache. This requires some sort of unique cacheID, usualy the classname of the subclass."""
    def __init__(self, engine, db, data, config, cacheID):
        udPolicy.__init__(self, engine, db, data, config)
        self.cacheID = cacheID
        self.cache = {}
        self.load_cache()
    def __del__(self):
        self.cache = self.data
        self.write_cache()
        
    def load_cache(self):
        """load cache from file"""
        try:
            cf = open('%s/%s.cache' % (self.config.cachedir, self.cacheID) , "r")
            self.cache = pickle.Unpickler(cf).load()
            cf.close()
            logging.debug('cachedUdPolicy: loaded cache file at %s/%s.cache', self.config.cachedir, self.cacheID)
        except Exception, err:
            #if no cache file, we are a new hosts or someone deleted our cache.
            logging.info('cachedUdPolicy: loading cache failed.')
            logging.debug(str(err))

    def write_cache(self):
        """write cache to file"""
        try:
            cf = open('%s/%s.cache' % (self.config.cachedir, self.cacheID) , "w")
            pickle.Pickler(cf, pickle.HIGHEST_PROTOCOL).dump(self.cache)
            cf.close()
            logging.debug('cachedUdPolicy: saved cache file at %s/%s.cache', self.config.cachedir, self.cacheID)
        except Exception, err:
            logging.warn('cachedUdPolicy: saving cache failed:%s', str(err))
