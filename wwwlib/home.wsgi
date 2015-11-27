# get/set homes for users.

import os.path
import sys
sys.path.append(os.path.dirname(__file__))

import ldap
import ldap.modlist
import functions as func
import logging
import re

import json

def application(env, send_headers):
    (error, db) = func.open_ud2_connection(env)
    if error:
        send_headers(error, [])
        return [db]
    method = env['REQUEST_METHOD']
    accept = env['HTTP_ACCEPT']
    if method in [ 'GET', 'HEAD' ]:
        send_headers("200 Ok", [('Content-Type','application/json')])
        if method == 'HEAD':
            return []
        if '/json' in accept:
            return ['["', '","'.join(db.home), '"]']
        # default to xml.
        return ['<udhomes>\n\t', '\n\t'.join(['<%s>%s</%s>' % ('home', home, 'home') for home in db.home]), '\n</udhomes>']
    send_headers("405 Method Not Allowed", [])
    return [ '' ]

