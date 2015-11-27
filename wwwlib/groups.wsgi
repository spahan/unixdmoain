from cgi import parse_qs
#import UniDomain.wwwlib as wwl
import sys, os
sys.path.append(os.path.dirname(__file__))
import functions as func
import ldap
from ldap.filter import escape_filter_chars

def application(env, send_headers):
    (error, db) = func.open_ud2_connection(env)
    if error:
        send_headers(error, [])
        return [db]
    method = env['REQUEST_METHOD']
    accept = env['HTTP_ACCEPT']
    if method in [ 'GET', 'HEAD' ]:
        # cheap filter. first and only respected arg must be 'term=...'
        parameters = parse_qs(env['QUERY_STRING'])
        if not 'term' in parameters:
            filter = ''
            query='(objectClass=posixGroup)'
        elif len(parameters['term']) == 0:
            filter = ''
            query='(objectClass=posixGroup)'
        else:
            filter = escape_filter_chars(parameters['term'][0])
            query = '(&(objectClass=posixGroup)(|(cn=%s*)(gidNumber=%s*)))' % (filter, filter)
        try:
            res = db.conn.search_s(db.config.ldapauthen, ldap.SCOPE_SUBTREE, query)
        except ldap.NO_SUCH_OBJECT:
            send_headers('404 Not Found', [])
            return []
        if 'text/html' in accept:
            ctype = 'text/html'
            cdata =  groups_html(filter,res)
        elif 'application/xml' in accept:
            ctype = 'application/xml'
            cdata = groups_xml(filter,res)
        else:
            # default to json as the webinterface likes that.
            ctype = 'application/json'
            cdata = groups_json(filter,res)
        send_headers("200 Ok", [('Content-Type', ctype)])
        if method == 'HEAD':
            return []
        return cdata
    send_headers("405 Method Not Allowed", [])
    return []


def groups_html(query,ldapdata):
    data = ['<html><head><title>groups for %s</title></head><body><ul>' % query]
    data.extend(['<li id="%s">%s <i style="font-size:small">(%s)</i></li>' % (dn,at['cn'][0],at['gidNumber'][0]) for (dn,at) in ldapdata])
    data.append('</ul></body></html>')
    return data

def groups_xml(query, ldapdata):
    data = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><grouplist><query>%s</query>' % query]
    data.extend(['<group><id>%s</id><gidNumber>%s</gidNumber><name>%s</name></group>' % (dn,at['gidNumber'][0],at['cn'][0]) for (dn, at) in ldapdata])
    data.append('</grouplist>')
    return data

def hasMemberUid(group):
    if 'memberUid' in group:
        return 'true'
    return 'false'

def groups_json(query,ldapdata):
    data = '['
    data += ','.join(['{"id":"%s", "group":"%s (%s)", "gidNumber":"%s", "name":"%s", "hasMembers":%s}' % (dn,at['cn'][0],at['gidNumber'][0],at['gidNumber'][0], at['cn'][0], hasMemberUid(at)) for (dn,at) in ldapdata])
    data += ']'
    return [data]
