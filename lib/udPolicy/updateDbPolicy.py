# coding: utf-8
"""
update the host record in database.

"""

import UniDomain.udPolicy.udPolicy as udPolicy
import logging

class updateDbPolicy(udPolicy.udPolicy):
    """ just a wrapper for a cfengine policy."""
    def __init__(self, engine, db, data, config):
        udPolicy.udPolicy.__init__(self, engine, db, data, config)
        
    def update(self):
        if not self.db.update_dnsRecord():
            logging.warning('updateDbPolicy: failed to update host data in database.')
