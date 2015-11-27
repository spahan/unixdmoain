#!/usr/bin/env python2
# coding: utf-8 
"""
THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
FOR LICENCE DETAILS SEE share/LICENSE.TXT

(c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>

Script to register a new host into your domain
Syntax: hostreg

Options:
    help - this help
"""

import os
import sys
import logging
import socket
import shutil
from UniDomain import Classes
from UniDomain import functions

import time

def askName():
    print 'The current hostname is \'%s\'\n' % functions.getlocalhostname()
    while True:
        raw = raw_input("please give the FULL QUALIFIED DOMAIN NAME for this host (leave empty to use current) : ")
        if raw == '': 
            return functions.getlocalhostname()
        elif raw.count('.') < 1: 
            print 'you want register a top level domain? Try again\n'
        else:
            return raw

def askTarget(db):
    if len(db.home) == 0: return False
    if len(db.home) == 1: return db.home[0]
    print 'Multiple domains configured. Choose one:'
    for i in xrange(0,len(db.home)): 
        print '%2i: %s' % (i, db.home[i])
    while True:
        try:
            return db.home[int(raw_input('which target to use? (0-%i):' %len(db.home)),10)]
        except Exception, e:
            logging.debug('bad input throws %s', e)

def askClasses():
    print 'Specify any classes you want add for this host (one per line, end with newline)'
    classes= []
    input = raw_input('class : ')
    while input:
        classes.append(raw_input)
        input = raw_input('class : ')
    return classes

def askPolicies():
    print 'Specify any policies you want set for this host (one per line, end with newline)'
    policies = []
    input = raw_input('policy : ')
    while input:
        policies.append(input)
        input = raw_input('policy : ')
    return policies

if __name__ == "__main__": 
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        logging.basicConfig(level=logging.DEBUG)
    config = Classes.Config(plugin_authen='krb5_login')
    try:
        authen = Classes.Authen(config).authenticate()
    except IndexError, e:
        print 'Authentication error (wrong password?)'
        sys.exit(1)
    db = Classes.DB(authen).connect()
    if not db:
        print 'db connection error'
        sys.exit(2)
    
    fqdn = askName()
    functions.set_hostname(fqdn)

    target = askTarget(db)
    classes = askClasses()
    policies = askPolicies()
    args = {}
    if len(policies) > 0:
        args['cfPolicy'] = ('policyClass',policies)

    logging.debug('adding %s to %s' % (fqdn, target))
    if not db.add_host(fqdn, target, classes, **args):
        logging.error('cant add host to ldap')
        sys.exit(5)
    if not authen.add_host(fqdn):
        logging.critical('cant add host to authen. (but host was added to database!)')
        sys.exit(6)
    if not authen.get_service_keytab('host', fqdn):
        logging.critical('error getting host keytab')
        sys.exit(7)
    if not authen.add_service('nfs', fqdn):
        logging.critical('can not add nfs principal to authen.')
        sys.exit(6)
    if not authen.get_service_keytab('nfs', fqdn):
        logging.critical('error getting nfs keytab')
        sys.exit(7)
