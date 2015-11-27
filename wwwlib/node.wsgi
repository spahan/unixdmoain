import ldap
import ldap.filter
import UniDomain.Classes
import sys, os
sys.path.append(os.path.dirname(__file__))
import functions as func
import os.path
import time
import logging
import urllib
from cgi import parse_qs
import json

def application(env, send_headers):
    logging.basicConfig(level=logging.DEBUG)
    (error, db) = func.open_ud2_connection(env)
    if error:
        send_headers(error, [])
        return [db]
    (error, id) = func.parse_id(env['PATH_INFO'].strip('/'), db)
    if error:
        send_headers(error, [])
        return [id]
    method = env['REQUEST_METHOD']
    accept = env['HTTP_ACCEPT']
    # GET node data
    if method in [ 'GET', 'HEAD' ]:
        (error, data) = get_node(db, id)
        if error:
            send_headers( error, [])
            return [data]

        if '/python' in accept:
            send_headers("200 Ok", [('Content-Type','application/python')])
            if method == 'HEAD':
                return []
            return [prepare_python(data).__repr__().replace(' ','')]
        # default to xml.
        send_headers("200 Ok", [('Content-Type','application/xml')])
        if method == 'HEAD':
            return []
        return prepare_xml_data(data)
    # POST edit attribute.
    elif method in [ 'POST' ]:
        try:
            request_body_size = int(env.get('CONTENT_LENGTH', 0))
        except (ValueError):
            send_headers("400 Bad Request",[])
            return ['bad content length']
        request_body = env['wsgi.input'].read(request_body_size)
        params= parse_qs(request_body)
        try:
            if 'add' in params['action']:
                (status, info) = add_attribute(db, id, params['attribute'][0], urllib.unquote(params['value'][0]))
            elif 'delete' in params['action']:
                (status,info) = delete_attribute(db, id, params['attribute'][0], urllib.unquote(params['value'][0]))
            elif 'change' in params['action']:
                (status, info) = change_attribute(db, id, params['attribute'][0], urllib.unquote(params['oldValue'][0]), urllib.unquote(params['newValue'][0]))
            elif 'addPol' in params['action']:
                (status, info) = add_policy(db, id, params['policy'][0], params['attribute'][0], urllib.unquote(params['value'][0]))
            elif 'deletePol' in params['action']:
                (status, info) = delete_policy(db, id, params['policy'][0], params['attribute'][0], urllib.unquote(params['value'][0]))
            elif 'changePol' in params['action']:
                (status, info) = change_policy(db, id, params['policy'][0], params['attribute'][0], urllib.unquote(params['value'][0]))
            else:
                (status, info) = ("400 Bad Request", "bad action")
        except IndexError, e:
            (status, info) = ("400 Bad Request", "missing fields.")
        send_headers( status, [])
        return [info]
    send_headers("405 Method Not Allowed", [])
    return [ '' ]

def prepare_python(data):
    """create a python representation from the internal data object."""
    (id, type, atts, ud2) = data
    return [id, type, atts, ud2.data, ud2.policies]

def prepare_xml_data(data):
    """ create a xml representation from the internal data object.
        @param data: the data blob from get_node()
        @return: a array of strings to return to the wsgi module
     """
    (id, type, atts, ud2) = data
    req = []
    req.append('<node id="%s" class="%s">' % (id.replace(' ',''),type.lower()))
    req.extend(ldap2xml(id.replace(' ',''), atts, 'info'))
    if ud2:
        req.append('<sources>')
        req.append('<ud2>')
        for at in ud2.data:
            for (val, src) in ud2.data[at]:
                req.append('<%s name="%s">%s</%s>' % (at,val,src.replace(' ',''),at))
        req.append('</ud2>')
        req.append('<policies>')
        for (pol) in ud2.policies:
            for (pid, pdict) in ud2.policies[pol]:
                req.extend(ldap2xml(pid.replace(' ',''), pdict, pol, src=pid.replace(' ','').split(',',1)[1]))
        req.append('</policies>')
        req.append('</sources>')
        reducedPolicy = ud2.getPolicies()
        req.append('<pre>%s</pre>' % reducedPolicy)
        req.append('<settings>')
        for pol in reducedPolicy:
            if pol == 'sudoPolicy':
                # very dirty hack. but...somehow our xsl stylesheet does not like the word sudo.
                req.append('<aaaaPolicy>')
                for at in reducedPolicy[pol]:
                    for va in reducedPolicy[pol][at]:
                        req.append('<%s>%s</%s>' % (at,va,at))
                req.append('</aaaaPolicy>')
            else:
                req.append('<%s>' % pol)
                for at in reducedPolicy[pol]:
                    for va in reducedPolicy[pol][at]:
                        req.append('<%s>%s</%s>' % (at,va,at))
                req.append('</%s>' % pol)
        req.append('</settings>')
    req.append('</node>')
    return req

def ldap2xml(dn, attributes, name, **args):
    """ get xml representation of a ldap node.
        the node will be a tag with 'name' as name
        the node will have a attribute 'id' with its DN and a attribute 'name' with its name.
        any additional arguments are key/value pairs to insert as node attributes.
        @param dn: the dn of this ldap node
        @param attributes: a dictionary with
            attribute -> list of attribute values.
        @param **args: additional key=value to add
        @return: a string representation of this node.
    """
    tmp = []
    tmp.append('<%s dn="%s" name="%s"' % (name, dn, dn.split(',',1)[0].split('=')[1]))
    for at in args:
        tmp.append(' %s="%s"' % (at, args[at]))
    tmp.append('>')
    for at in attributes:
        for va in attributes[at]:
            tmp.append('<%s>%s</%s>' % (at,va,at))
    tmp.append('</%s>' % name)
    return tmp
    
def get_node(db, id):
    """ collect data about this object from the database backend.
        @param db: the db connectionto use
        @param id: the id of the object to retrieve
        @return: a tuble (error, data)
            if no error occured error will be a False value and data is a collection of hostinfo
            on error, the error is a http response code and data is the error string
        """
    logging.debug('get_node with id %s', id)
    try:
        atts = db.conn.search_s(id, ldap.SCOPE_BASE, '(objectClass=*)')[0][1]
        myclass = 'ou'
        ud2data = {}
        for t in atts['objectClass']:
            if t.lower() in ['udhostcontainer','uddomain']:
                myclass = t
                ud2data = db.get_container_data(id)
                break
            elif t.lower() == 'udhost': 
                myclass = t
                ud2data = db.get_host_data(id)
                break
            elif t.lower() in [ 'udgroup']: 
                myclass = t
                ud2data = db.get_udGroup_data(id.split(',')[0].split('=')[1])
                break
            elif t.lower() in [ 'organizationalunit' ]:
                myclass = 'ou'
                ud2data = db.get_container_data(id)
    except ldap.NO_SUCH_OBJECT:
        return ('404 Not Found', 'Sorry, no such Object in your domain')
    return (None, (id, myclass, atts, ud2data))

def add_attribute(db,id,attribute, value):
    """ set a node attribute.
        @param db: database connection
        @param id: id of object to change
        @param attribute: attribute name
        @param value: value to add
    """
    logging.debug('add_attribute: %r, %r, %r' % (id, attribute, value))
    #  ['udGroup','description', 'uid', 'unixGroup', 'policyClass']
    if not attribute.lower() in ['description', 'udgroup']:
        return ('403 Forbidden', "Attribute add not allowed for this attribute")
    try:
        attributes = db.conn.search_s(id, ldap.SCOPE_BASE, '(objectClass=*)', [attribute])[0][1]
    except ldap.NO_SUCH_OBJECT:
        return ('404 Not Found', "No such Object in your domain")
    modlist = []
    rValue = value
    # if already in, do not add again. Maybe UI is slow or ldap did not sync fast enough
    if not attribute in attributes.keys() or not rValue in attributes[attribute]:
        logging.info('wwwlib:node:PUT: adding %s=%s to %s' % (attribute,rValue,id))
        modlist.append((ldap.MOD_ADD, attribute, rValue))
    logging.debug('add_attribute: modlist is %r' % modlist)
    if len(modlist) > 0:
        try:
            db.conn.modify_s(id,modlist)
        except Exception, err:
            return('500 Internal Server Error', 'Something went wrong trying to add the attributes %s' % err)
    #FIXME: ugly hack to let ldap servers sync.
    # TODO: does this work?
    time.sleep(1)
    return ('204 Ok', '')

def delete_attribute(db,id,attribute, value):
    """ Delete a ldap node attribute.
        @param db: database connection
        @param id: id of object to change
        @param attribute: attribute name
        @param value: value to delete
    """
    logging.debug("delete_attribute: %r, %r, %r" % (id, attribute,value))
    if not attribute.lower() in ['udgroup','uid','unixgroup','policyclass','description']:
        return ('403 Forbidden', "can not delete attribute'")
    try:
        attributes = db.conn.search_s(id, ldap.SCOPE_BASE, '(objectClass=*)', [attribute])[0][1]
    except ldap.NO_SUCH_OBJECT:
        return('404 Not Found', "No such Object in your domain")
    logging.debug("delete_Attribute: editing %r" % attributes)
    modlist = []
    if attribute in attributes.keys():
        # DELETE is idempotent so we may already delete the attribute.
        if value in attributes[attribute]:
            logging.info('wwwlib:node:DELETE: deleting %s=%s from %s' % (attribute,value,id)) 
            modlist.append((ldap.MOD_DELETE, attribute, value))
    logging.debug('delete_attribute: modlist is %r' % modlist)
    if len(modlist) > 0:
        try:
            db.conn.modify_s(id,modlist)
        except Exception, err:
            ('500 Internal Server Error', "Something Bad happened while try modify your Object.\n Maybe the ldap server is stupid?\n Anyway, try again and complain to the admins if it does not work.")
    #FIXME: ugly hack to let ldap servers sync.
    time.sleep(1)
    return ('204 No Content', '')

def change_attribute(db,id,attribute,oldValue, newValue):
    """ change a ldap node attribute from oldValue to newValue.
        @param db: database connection
        @param id: id of object to change
        @param attribute: attribute name
        @param oldValue: old attribute value
        @param newValue: new attribute value
    """
    logging.debug('change_Attribute: %r, %r, %r, %r' % (id, attribute, oldValue, newValue))
    if not attribute.lower() in ['description']:
        return ('403 Forbidden', "Attribute change not allowed for this attribute")
    try:
        attributes = db.conn.search_s(id, ldap.SCOPE_BASE, '(objectClass=*)', [attribute])[0][1]
    except ldap.NO_SUCH_OBJECT:
        return ('404 Not Found', "No such Object in your domain")
    modlist = []
    if attribute in attributes.keys():
        if oldValue in attributes[attribute]:
            logging.info('wwwlib:node:DELETE: deleting %s=%s from %s' % (attribute,oldValue,id))
            modlist.append((ldap.MOD_DELETE, attribute, oldValue))
        if not newValue in attributes[attribute]:
            logging.info('wwwlib:node:PUT: adding %s=%s to %s' % (attribute,newValue,id))
            modlist.append((ldap.MOD_ADD, attribute, newValue))
    logging.debug('change_attribute: modlist is %r' % modlist)
    if len(modlist) > 0:
        try:
            db.conn.modify_s(id,modlist)
        except Exception, err:
            return('500 Internal Server Error', 'Something went wrong trying to add the attributes %s' % err)
    #FIXME: ugly hack to let ldap servers sync.
    # TODO: does this work?
    time.sleep(1)
    return ('204 Ok', '')

def add_policy(db,id,policy,attribute,value):
    """ add attribute to policy.
        if the object does not have the policy sub-object, we add it.
        @param db: database connection
        @param id: id of object to change
        @param policy: to what policy we add this attribute
        @param attribute: which attribute to add
        @param value: the value to add
    """
    logging.debug('add_policy: %r, %r, %r, %r' % (id, policy, attribute, value))
    # check if this object exists.
    try:
        db.conn.search_s(id, ldap.SCOPE_BASE, '(objectClass=*)', ['objectClass'], 1)
    except ldap.NO_SUCH_OBJECT:
        return ('404 Not Found', "No such Object in your domain")
    try:
        attributes = db.conn.search_s('cn=%s,%s' % (policy, id), ldap.SCOPE_BASE, '(objectClass=udPolicy)')[0][1]
        modlist = []
        # check if the attribute is already set.
        logging.debug('add_policy: ats are %s', attributes)
        logging.debug('add_policy: we want %s=%s', attribute, value)
        if attribute in attributes.keys():
            if not value in attributes[attribute]:
                modlist.append((ldap.MOD_ADD, attribute, value))
        else:
            modlist.append((ldap.MOD_ADD, attribute, value))
        logging.debug('add_policy: modlist is %r' % modlist)
        if len(modlist) > 0:
            try:
                db.conn.modify_s('cn=%s,%s' % (policy, id),modlist)
            except Exception, err:
                return('500 Internal Server Error', 'Something went wrong trying to add the attributes %s' % err)
    except ldap.NO_SUCH_OBJECT:
        # add the policy object.
        logging.debug('add_policy: create new %s object' % policy)
        try:
            db.conn.add_s('cn=%s,%s' % (policy, id), [('objectClass', ['top','udPolicy']), (attribute, [value])])
        except Exception, err:
            return('500 Internal Server Error', 'Something went wrong trying to add the attributes %s' % err)
    #FIXME: ugly hack to let ldap servers sync.
    # TODO: does this work?
    time.sleep(1)
    return ('204 Ok', '')
    
def delete_policy(db,id,policy,attribute,value):
    """ delete attribute from a policy.
        @param db: database connection
        @param id: id of object to change
        @param policy: from what policy we remove this attribute
        @param attribute: which attribute to remove
        @param value: the value to remove
    """
    logging.debug('delete_policy: %r, %r, %r, %r' % (id, policy, attribute, value))
    # check if this object exists.
    try:
        attributes =  db.conn.search_s('cn=%s,%s' % (policy, id), ldap.SCOPE_BASE, '(objectClass=udPolicy)')[0][1]
    except ldap.NO_SUCH_OBJECT:
        return ('404 Not Found', "No such policy in your domain")
    modlist = []
    if attribute in attributes.keys():
        if value in attributes[attribute]:
            modlist.append((ldap.MOD_DELETE, attribute, value))
    logging.debug('delete_policy: modlist is %r' % modlist)
    if len(modlist) > 0:
        try:
            db.conn.modify_s('cn=%s,%s' % (policy, id), modlist)
        except Exception, err:
            return('500 Internal Server Error', 'Something went wrong trying to add the attributes %s' % err)
    #FIXME: ugly hack to let ldap servers sync.
    # TODO: does this work?
    time.sleep(1)
    return ('204 Ok', '')

