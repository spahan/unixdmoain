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
from UniDomain import functions
from optparse import OptionParser
import sys
import logging
import subprocess

# this is hacky. we should not depend on a built in list of policies.
# however, we do not know what policies exists a priori.
# Checking UniDomain.udPolicy dir is hard as there are some helpers too.
known_policies = ['user', 'group', 'cf', 'sudo', 'localHome']
curl = ['curl', '--header', 'Accept:application/python', '--silent','--delegation', 'always', '--negotiate', '-u:' ,'--insecure']
base_url = 'https://urz-spahan00.urz.unibas.ch/domad/node/'

def add_policy(itemID, policy, value):
    logging.debug("add %s to %s (%s)", value, policy, itemID)
    if policy == 'user': att = 'attribute=uid'
    elif policy == 'group' : att = 'attribute=posixGroup'
    elif policy == 'cf': att = 'attribute=policyClass'
    elif policy == 'sudo': att = 'attribute=uid'
    else: return 1
    post = ['-d', 'action=addPol', '-d', 'policy=%sPolicy' % policy, '-d', att, '-d', 'value=%s' % value]
    sub = subprocess.Popen( curl + post + [base_url + itemID], stdout=subprocess.PIPE)
    return sub.wait()
    
def delete_policy(itemID, policy, value):
    logging.debug("delete %s from %s (%s)", value, policy, itemID)
    if policy == 'user': att = 'attribute=uid'
    elif policy == 'group' : att = 'attribute=posixGroup'
    elif policy == 'cf': att = 'attribute=policyClass'
    elif policy == 'sudo': att = 'attribute=uid'
    else: return 1
    post = ['-d', 'action=deletePol', '-d', 'policy=%sPolicy' % policy, '-d', att, '-d', 'value=%s' % value]
    sub = subprocess.Popen( curl + post + [base_url + itemID], stdout=subprocess.PIPE)
    return sub.wait()

def addGroup_policy(itemID, policy, value):
    logging.debug("addGroup %s to %s (%s)", value, policy, itemID)
    post = ['-d', 'action=addPol', '-d', 'policy=%sPolicy' % policy, '-d', 'attribute=unixGroup', '-d', 'value=%s' % value]
    sub = subprocess.Popen( curl + post + [base_url + itemID], stdout=subprocess.PIPE)
    return sub.wait()

def deleteGroup_policy(itemID, policy, value):
    logging.debug("deleteGroup %s to %s (%s)", value, policy, itemID)
    post = ['-d', 'action=deletePol', '-d', 'policy=%sPolicy' % policy, '-d', 'attribute=unixGroup', '-d', 'value=%s' % value]
    sub = subprocess.Popen( curl + post + [base_url + itemID], stdout=subprocess.PIPE)
    return sub.wait()

def disable_policy(itemID, policy, value):
    logging.debug("disable %s to %s (%s)", value, policy, itemID)
    post = ['-d', 'action=addPol', '-d', 'policy=%sPolicy' % policy, '-d', 'attribute=disabledPolicyData', '-d', 'value=%s' % value]
    sub = subprocess.Popen( curl + post + [base_url + itemID], stdout=subprocess.PIPE)
    return sub.wait()
def enable_policy(itemID, policy, value):
    logging.debug("enable %s to %s (%s)", value, policy, itemID)
    post = ['-d', 'action=deletePol', '-d', 'policy=%sPolicy' % policy, '-d', 'attribute=disabledPolicyData', '-d', 'value=%s' % value]
    sub = subprocess.Popen( curl + post + [base_url + itemID], stdout=subprocess.PIPE)
    return sub.wait()

def list_policy(itemID, policy):
    logging.debug("list %s (%s)", policy, itemID)
    sub = subprocess.Popen(curl + [base_url + itemID], stdout=subprocess.PIPE)
    raw = ''
    for line in sub.stdout:
        raw += line
    try:
        data = eval(raw) # simple and fast, but hacky.
    except SyntaxError, err:
        logging.critical("server returned: %s" % raw)
        sys.exit(9)
    print "\nThese are the %s settings for %s:" % (policy, itemID)
    try:
        for (id,atts) in data[4][policy + 'Policy']:
            if id.endswith(itemID):
                cs = ''
            else:
                cs = '(inherited)'
            [sys.stdout.write(" %s : %s %s\n" %(at,atts[at],cs)) for at in atts if not at in ['objectClass','cn']]
    except KeyError, err:
        pass
 
    # legacy compatiblilty.
    if policy == 'user' and len(data[3]['uid']) > 0:
        sys.stdout.write(" uid : %s (legacy)\n" % ([uid for (uid,src) in data[3]['uid']])) 
    if policy == 'group' and len(data[3]['unixGroup']) > 0:
        sys.stdout.write(" unixGroup : %s (legacy)\n" % ([group for (group, src) in data[3]['unixGroup']]))
    if policy == 'cf' and len(data[3]['policyClass']) > 0:
        sys.stdout.write(" policyClass : %s (legacy)\n" % ([pol for (pol,src) in data[3]['policyClass']]))

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [host] <policy> action", description="Edit host policy settings. If host is not specified, the settings for the local host are updated. Use -p for a list of known policies and actions.")
    extended_help="""Available policies and their options:
user:
    list - list current user settings
    add/delete <uid> - adds or removes a user 
    addGroup/deleteGroup <gid> - adds or removes users from a given group.
    disable/enable <uid> - disables a specific uid. Mostly used to remove one person from a group.
group:
    list - list current group settings
    add/delete <gid> - adds or removes a group from the system.
class:
    list - list current cfengine classes
    add/delete <cfengine-class> - adds or removes a cfengine class.
sudo:
    list - list current sudoer settings.
    add/delete <uid> - adds or removes a sudoer
    addGroup/deleteGroup - add or remove a group from sudoers.
    disable/enable  - disable a specific uid. Mostly used to remove one person from a group.
locaHome:
    list - list localhome settings
"""
    parser.add_option("-j", action="store_true", dest="janitor", help="use janitor account", default=False)
    parser.add_option("-v", action="store_true", dest="debug", help="be verbose", default=False)
    parser.add_option("-p", action="store_true", dest="extended_help", help="show known policies and their actions", default=False)
    (options, args) = parser.parse_args()
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    if options.extended_help:
        print extended_help
        sys.exit(0)
    
    if len(args) < 2:
        logging.critical('invalid syntax')
        parser.print_usage()
        sys.exit(1)
    # check for hostname and policy to edit.
    if args[0] in known_policies:
        # no hosts specified. use local host name.
        hostname = 'host/' + functions.getlocalhostname()
        policy = args.pop(0)
    elif args[1] in known_policies:
        hostname = args.pop(0)
        if not hostname.startswith('host/'):
            hostname = 'host/' + hostname
        policy = args.pop(0)
    else:
        logging.critical('Invalid syntax, unknown policy specified')
        parser.print_usage()
        sys.exit(1)
    # get ticket
    if options.janitor:
        config = Classes.Config(krb5keytab="/root/janitor/janitor.keytab")
    else:
        if args[0] == 'list' :
            # use host keytab. else we have to ask for the domad pw all the time.
            config = Classes.Config()
        else:
            # we want change things. needs domad ticket
            config = Classes.Config(plugin_authen="krb5_login")
    authen = authen = Classes.Authen(config).authenticate()
    if not authen:
        sys.exit(2)
    db = Classes.DB(authen).connect()
    if not db:
        sys.exit(4)
    hostid = db.get_itemID(hostname)
    if not hostid:
        logging.warn('Host %s not found.' % hostname)
        sys.exit(5)

    if args[0] == 'list':
        sys.exit(list_policy(hostid, policy))
    if not len(args) == 2:
        logging.critical('Invalid argument for action')
        parser.print_usage()
        sys.exit(1)
    if args[0] == 'add':
        sys.exit(add_policy(hostid, policy, args[1]))
    elif args[0] == 'delete':
        sys.exit(delete_policy(hostname, policy, args[1]))
    elif policy in ['user','sudo']:
        if args[0] == 'addGroup':
            sys.exit(addGroup_policy(hostname, policy, args[1]))
        elif args[0] == 'deleteGroup':
            sys.exit(deleteGroup_policy(hostname, policy, args[1]))
        elif args[0] == 'disable':
            sys.exit(disable_policy(hostname, policy, args[1]))
        elif args[0] == 'enable':
            sys.exit(enable_policy(hostname, policy, args[1]))
        
    logging.critical('bad action for %s policy' % policy)
    parser.print_usage()
    sys.exit(1)
