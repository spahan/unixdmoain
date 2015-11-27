"""This represents a Node list.
To read a Node list, one has to give the parent DN.
To move around items in the tree, this representation supports post methodes.
The Put method allows to create new nodes (very restricted subset for domads)"""
#from mod_python import apache
#from rest import writeError
import os.path
import sys
sys.path.append(os.path.dirname(__file__))

import ldap
import ldap.modlist
import UniDomain.Classes
from UniDomain.plugins.ldapdb import norm_dn

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
    (error, id) = func.parse_id(env['PATH_INFO'].strip('/'), db)
    if error:
        send_headers(error, [])
        return [id]
    method = env['REQUEST_METHOD']
    accept = env['HTTP_ACCEPT']
    if method in [ 'GET', 'HEAD' ]:
        (error, childs) = get_childs(db, id)
        if error:
            send_headers( error, [])
            return [childs]
        childs = make_child_tree(id, childs)
        if '/json' in accept:
            send_headers("200 Ok", [('Content-Type','application/json')])
            if method == 'HEAD':
                return []
            return [ json.JsonWriter().write(childs) ]
        # default to xml.
        send_headers("200 Ok", [('Content-Type','application/xml')])
        if method == 'HEAD':
            return []
        return [ write_xml_tree(childs['childs'][id.split(',')[0]]) ]
    elif method == 'POST':
        input = env['wsgi.input'].read(int(env['CONTENT_LENGTH']));
        (error, message) = move_node(id, input, db)
        send_headers(error, [])
        return [message]
    elif method == 'PUT':
        (nType, nName) = env['wsgi.input'].read(int(env['CONTENT_LENGTH'])).split('=', 1);
        
        (error, message) = add_node(id, nType, nName, db)
        send_headers(error, [])
        return [message]
    elif method == 'DELETE':
        (error,message) = delete_node(id, db)
        send_headers(error,[])
        return [message]
    send_headers("405 Method Not Allowed", [])
    return [ '' ]

# functions for GET
def write_xml_tree(node):
    """ create xml output from internal tree """
    result = '<%(class)s id="%(id)s" name="%(name)s" description="%(desc)s"' % node['data']
    if len(node['childs']) > 0:
        result += '>'
        for c in node['childs']:
            result += write_xml_tree(node['childs'][c])
        result += '</%s>' % node['data']['class']
    else:
        result += '/>'
    return result

def make_child_tree(id, childs):
    """ create a tree representation from the list of items"""
    def split_with_root(dn,root):
        if dn.lower().endswith(root.lower()):
            return dn[:-(len(root)+1)].split(',')
        else:
            return False

    def add(dna, node, data):
        if len(dna) == 0:
            node['data'] = data
        else:
            name = dna.pop().lower()
            if name not in node["childs"]:
                node["childs"][name] = {"childs":{}}
            add(dna, node["childs"][name], data)
    root = id.replace(', ',',').split(',',1)[1]
    tree = {'childs':{}}
    for c in childs:
        add(split_with_root(c['id'], root), tree, c)
    return tree
    
def reduce_child(id,at):
    """ collate some attributes """
    try:
        name = at[id.split('=',1)[0]][0]
    except AttributeError:
        name = 'i haz no name?'
    myclass = None
    for t in at['objectClass']:
        if t.lower() in ['udgroup','udhost','udhostcontainer','uddomain']: 
            myclass = t.lower()
            break
    if myclass == None: myclass = 'ou'
    try:
        description = at['description'][0]
    except:
        description = 'No information available'
    return {'id':id, 'name':name, 'class':myclass, 'desc':description}

def deleteTree(db,dn):
    """delete dn and all of its childs"""
    reslist = db.conn.search_s(dn, ldap.SCOPE_ONELEVEL, attrsonly=1)
    for child in reslist:
        deleteTree(db,child[0])
    db.conn.delete_s(dn)
    
objectClasses = ['udDomain','udHost','udHostContainer','udGroup','organizationalUnit']
def get_childs(db, id):
    try:
        reslist = [db.conn.search(id,ldap.SCOPE_SUBTREE, '(objectClass=%s)' % obj, ['cn', 'ou', 'objectClass', 'description']) for obj in objectClasses]
        #collect all results.
        res = sum([db.conn.result(resid)[1] for resid in reslist],[]);
    except ldap.NO_SUCH_OBJECT:
        return ('404 Not Found', "Sorry, no such Object in your domain")
    return ( None, [reduce_child(norm_dn(dn),att) for (dn,att) in res ] )

def move_node(oldDN, newDN, db):
    if newDN == oldDN:
        return ('403 Forbidden', 'Source and Target are the same.')
    if not any([newDN.endswith(home) for home in db.home]):
        return ('403 Forbidden', 'You are not allowed to change this Object. (Bad Target Domain)')
    newRDN, newPDN = newDN.split(',',1)
    oldRDN, oldPDN = oldDN.split(',',1)
    logging.debug("move/rename %s.\n\tName: %s -> %s\n\tParent:%s -> %s" % (oldDN, oldRDN, newRDN, oldPDN, newPDN))
    #check if the old Object actualy exists
    try:
        objectAttributes = db.conn.search_s(oldDN, ldap.SCOPE_BASE)[0][1]
    except ldap.NO_SUCH_OBJECT:
        return ('404 Not Found' 'Sorry, no such Object in your domain')
    #check renaming
    if newRDN != oldRDN:
        otype,name = newRDN.split('=')
        if not oldRDN.startswith(otype + '='):
            return ('400 Bad Request', 'You can not change the tpye of this object')
        if not re.match(r"^[a-zA-Z0-9-]+$", name):
            return ('403 Forbidden', 'you can only use [a-zA-Z0-9-] in names')
        objectAttributes[otype] = [name]
        #only allow certain types to be renamed (no hosts!)
        if len(set([t.lower() for t in objectAttributes['objectClass']]) & set(['udhostcontainer','udgroup','organizationalunit'])) == 0:
            return ('403 Forbidden', 'You can not rename this object')
    #check if target already exists.
    try:
        db.conn.search_s(newDN, ldap.SCOPE_BASE)
        return ('403 Forbidden', 'Target already exists')
    except ldap.NO_SUCH_OBJECT:
        pass
    #check new parent
    if newPDN != oldPDN:
        if oldDN.endswith(newDN):
            return ('403 Forbidden', 'Can not move this object into itself')
        try:
            parentAttributes = db.conn.search_s(newPDN, ldap.SCOPE_BASE, '(objectClass=*)', ['objectClass'])[0][1]
            if len(set([t.lower() for t in parentAttributes['objectClass']]) & set([ 'uddomain','udhostcontainer','udgroup','organizationalunit'])) == 0:
                return ('400 Bad Request', 'Can not move. (Bad Target type)')
        except ldap.NO_SUCH_OBJECT:
            return ('400 Bad Request', 'Can not move. (new parent not existent)')
    logging.debug('moving %s to %s.' % (oldDN,newDN))
    modlist = ldap.modlist.addModlist(objectAttributes)
    db.conn.add_s(newDN,modlist)
    moveChildNodes(db,oldDN, newDN)
    db.conn.delete_s(oldDN)
    return ('203 No Content', '')

# functions for POST (move/rename)
def moveChildNodes(db, olddn, newdn):
    """recursively move all childs from olddn to newdn."""
    reslist = db.conn.search_s(olddn,ldap.SCOPE_ONELEVEL)
    for dn,att in reslist:
        child = db.norm_dn(dn).split(',',1)[0]
        modlist = ldap.modlist.addModlist(att)
        db.conn.add_s(child + ',' + newdn,modlist)
        moveChildNodes(db,dn, child + ',' + newdn)
        db.conn.delete_s(dn)

def add_node(parentID, nodeType, nodeName, db):
    """Create a new child node.
    This only is required to create ou or udGroup or udHostContainer items.
    required parameters
        type = the udtype (ou,udGroup,udHostContainer)
        name = name of the new node."""
    try:
        #name sanitation, be strict what we allow here, only allow hostname chars from rfc 1123
        if re.match(r"^[a-zA-Z0-9-]+$", nodeName):
            if nodeType == 'ou':
                ndn = 'ou=%s,%s' % (nodeName, parentID)
                nat = [('objectClass',['organizationalUnit'])]
            elif nodeType == 'udGroup':
                ndn = 'cn=%s,%s' % (nodeName,parentID)
                nat = [('objectClass', ['top', 'udGroup']),('description', 'a newly created udGroup Object.')]
            elif nodeType == 'udHostContainer':
                ndn = 'ou=%s,%s' % (nodeName,parentID)
                nat = [('objectClass', ['top', 'udHostContainer']),('description', 'a newly created udHostContainer Object.'), ('udGroup',['defaults'])]
            else:
                return ("403 Forbidden", "Bad Object type specified.")
        else:
            return ('403 Forbidden', "Sorry. Only [a-zA-Z0-9-] are allowed in object names.")
        try:
            childs = db.conn.search_s(ndn,ldap.SCOPE_BASE, attrsonly=1)
            return ('409 Conflict', "Already exists.")
        except ldap.NO_SUCH_OBJECT:
            db.conn.add_s(ndn,nat)
            return ('204 No Content', '')
    except KeyError:
        return ('500 Internal Server Error', "Did not look like a valid request.")
    
def delete_node(id, db):
    """Delete this Node."""
    try:
        childs = db.conn.search_s(id,ldap.SCOPE_SUBTREE,'(&(&(!(objectClass=udHostContainer))(!(objectClass=udGroup)))(!(objectClass=organizationalUnit)))', attrsonly=1)
    except ldap.NO_SUCH_OBJECT:
        return ("404 Not Found", "did not found %s in your domain" % id)
    deleteTree(db,id)
    return ("204 No Content", '')

