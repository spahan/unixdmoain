#!/usr/bin/env python2
# coding: utf-8
"""
update routine for the client.
this should be run periodicaly (every hour).
"""
#THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
#FOR LICENCE DETAILS SEE share/LICENSE.TXT
#
#(c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
from UniDomain import Classes
from UniDomain import udPolicyEngine
import sys
import logging

def client_run():
    print("\n---------------------------------------------\nUniDomain managed system is updating account, group and policy settings ... \n---------------------------------------------\n")
    config = Classes.Config()
    authen = Classes.Authen(config).authenticate()
    if not authen:
        logging.critical('authentication of this host failed. Is this host registered in a domain? Network is up?')
        return 1
    # connect to database
    db = Classes.DB(authen).connect()
    if not db:
        logging.critical('can not connect to database.')
        return 2
    #get a AttributeCollection about this host
    hostAttributes = db.get_host_data(db.userID)
    logging.debug(hostAttributes.__str__())
    
    udPolicies = hostAttributes.getPolicies()

    # update the database. this is used for dead host detection.
    udPolicies['updateDbPolicy'] = None
    
    logging.info('instantiating udPolicyEngine with %i policies' % len(udPolicies))
    runner = udPolicyEngine.udPolicyEngine(udPolicies, db, config)
    logging.info('running udPolicyEngine.')
    runner.run()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        logging.basicConfig(level=logging.DEBUG)
    sys.exit(client_run())
