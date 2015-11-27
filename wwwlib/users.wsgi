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
    #(error, id) = func.parse_id(env['PATH_INFO'].strip('/'), db)
    #if error:
    #    send_headers(error, [])
    #    return [id]
    method = env['REQUEST_METHOD']
    accept = env['HTTP_ACCEPT']
    # GET node data
    if method in [ 'GET', 'HEAD' ]:
        # cheap filter. first and only respected arg must be 'term=...'
        parameters = parse_qs(env['QUERY_STRING'])
        if not 'term' in parameters:
            send_headers( '400 Bad Request', [])
            return []
        if len(parameters['term']) == 0:
            send_headers('400 Bad Request', [])
            return []
        filter = escape_filter_chars(parameters['term'][0])
        if len(filter) < 3:
            send_headers('403 Forbidden', [])
            return []
        try:
            res = db.conn.search_s(db.config.ldapauthen, ldap.SCOPE_SUBTREE, '(&(objectClass=person)(|(uid=%s*)(|(cn=%s*)(sn=%s*))))' % (filter, filter, filter))
        except ldap.NO_SUCH_OBJECT:
            send_headers('404 Not Found', [])
            return []
        if 'text/html' in accept:
            ctype = 'text/html'
            cdata =  users_html(res)
        elif 'application/xml' in accept:
            ctype = 'application/xml'
            cdata = users_xml(res)
        else:
            # default to json as the webinterface likes that.
            ctype = 'application/json'
            cdata = users_json(res)
        send_headers("200 Ok", [('Content-Type', ctype)])
        if method == 'HEAD':
            return []
        return cdata
    send_headers("405 Method Not Allowed", [])
    return []


def users_html(users):
    data = ['<html><head><title>users:%s</title></head><body><ul>' % id]
    data.append(''.join(['<li id="%s">%s %s</li>' % (dn,at['cn'][0],at['uid'][0]) for (dn,at) in users]))
    data.append('</ul></body></html>')
    return data

def users_xml(users):
    data = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><userlist><id>%s</id>' % id]
    data.append(''.join(['<user><id>%s</id><posixname>%s</posixname><name>%s</name></user>' % (dn,at['uid'][0],at['cn'][0]) for (dn, at) in users]))
    data.append('</userlist>')
    return data

def users_json(users):
    data = ['[']
    data.append(','.join(['{"id":"%s", "user":"%s, %s", "uid":"%s", "email":"%s"}' % (dn,at['cn'][0],at['uid'][0],at['uid'][0], 'seeAlso' in at and at['seeAlso'][0] or 'hasNoEmail') for (dn,at) in users]))
    data.append(']')
    return data
