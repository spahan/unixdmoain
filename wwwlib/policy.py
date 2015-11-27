"""Post policy changes."""
from mod_python import apache
from rest import writeError
import os.path
import ldap
import ldap.modlist
import UniDomain.Classes
import time
import urllib
import logging
import re


def write_xml_tree(req, node, first=True):
    req.write('<%(class)s id="%(id)s" name="%(name)s" description="%(desc)s"' % node['data'])
    #if first:
    #    req.write(' xmlns="http://urz.unibas.ch/namespaces/ud2tree"')
    if len(node['childs']) > 0:
        req.write('>')
        for c in node['childs']:
            write_xml_tree(req, node['childs'][c], False)
        req.write('</%s>' % node['data']['class'])
    else:
        req.write('/>')
    
def reduce_child(id,at):
    """helper to transform ldap data into tree data"""
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
    modifyTimestamp = at['modifyTimestamp'][0]
    return {'id':id, 'name':name, 'class':myclass, 'desc':description, 'modifyTimestamp': modifyTimestamp}

#:supported HTTP Request Methodes
allowedMethodes = ['POST','DELETE']
    
def moveChildNodes(db, olddn, newdn):
    """recursively move all childs from olddn to newdn."""
    reslist = db.conn.search_s(olddn,ldap.SCOPE_ONELEVEL)
    for dn,att in reslist:
        child = db.norm_dn(dn).split(',',1)[0]
        modlist = ldap.modlist.addModlist(att)
        db.conn.add_s(child + ',' + newdn,modlist)
        moveChildNodes(db,dn, child + ',' + newdn)
        db.conn.delete_s(dn)
        
def deleteTree(db,dn):
    """delete dn and all of its childs"""
    reslist = db.conn.search_s(dn, ldap.SCOPE_ONELEVEL, attrsonly=1)
    for child in reslist:
        deleteTree(db,child[0])
    db.conn.delete_s(dn)
    

#:For security reasons we only allow a specific subset of Object Classes to be read from ldap.
objectClasses = ['udDomain','udHost','udHostContainer','udGroup','organizationalUnit']
def GET(req,id):
    """Get a list of childs for this item.
    id is a itemID from other requests."""
    req.add_common_vars()
    config = UniDomain.Classes.Config(file=os.path.dirname(__file__) + '/../etc/www_conf.xml')
    domad = UniDomain.Classes.Authen(config).authenticate(ccpath=req.subprocess_env['KRB5CCNAME'])
    if not domad:
        return writeError(req, apache.HTTP_FORBIDDEN, "Can not validate kerberos Ticket Data")
    db = UniDomain.Classes.Author(config).authorize(domad.split('@')[0])
    if not db:
        return writeError(req, apache.HTTP_FORBIDDEN, "Database Connection failed for user %s" % (req.subprocess_env['REMOTE_USER']))
    if not id:
        id = db.domainID
    elif not id.endswith(config.ldapbase):
        id = db.get_itemID(id)
        if not id:
            return writeError(req, apache.HTTP_NOT_FOUND, "Sorry, no such Object in your domain")
    elif not id.endswith(db.domainID):
        return writeError(req, apache.HTTP_FORBIDDEN, "You are not allowed to see this Object.")
    try:
        reslist = [db.conn.search(id,ldap.SCOPE_SUBTREE, '(objectClass=%s)' % obj, ['cn', 'ou', 'objectClass', 'description', 'modifyTimestamp']) for obj in objectClasses]
        #collect all results.
        res = sum([db.conn.result(resid)[1] for resid in reslist],[]);
    except ldap.NO_SUCH_OBJECT:
        return writeError(req, apache.HTTP_NOT_FOUND, "Sorry, no such Object in your domain")
    if 'application/json' in req.headers_in['Accept']: return write_childs_json(req,db.norm_dn(id),[reduce_child(db.norm_dn(dn),att) for (dn,att) in res])
    elif 'text/xml' in req.headers_in['Accept']: return write_childs_xml(req,db.norm_dn(id),[reduce_child(db.norm_dn(dn),att) for (dn,att) in res])
    else: return write_childs_html(req,db.norm_dn(id),[reduce_child(db.norm_dn(dn),att) for (dn,att) in res])

def POST(req,id):
    """Add a attribute to a policy
        shall have request fields of form attribute=value."""
    """Rename a node, can be used to move too.
    Requires form fields:
        ndn is the new dn for this object.
    id is the node to move."""
    #IMPROVE: try check for confilcts.
    req.add_common_vars()
    config = UniDomain.Classes.Config(file=os.path.dirname(__file__) + '/../etc/www_conf.xml')
    domad = UniDomain.Classes.Authen(config).authenticate(ccpath=req.subprocess_env['KRB5CCNAME'])
    if not domad: # cant happen or apache auth is set up wrong.
        return writeError(req, apache.HTTP_FORBIDDEN, "Can not validate kerberos Ticket Data")
    db = UniDomain.Classes.Author(config).authorize(domad.split('@')[0])
    if not db:
        return writeError(req, apache.HTTP_FORBIDDEN, "Database Connection failed for user %s" % (req.subprocess_env['REMOTE_USER']))
    if not id.endswith(db.domainID):
        return writeError(req, apache.HTTP_FORBIDDEN, "You are not allowed to change this Object. (Bad Source Domain)")
    try: 
        ndn = urllib.unquote(req.form['ndn'])
    except AttributeError: 
        return apache.HTTP_BAD_REQUEST
    if ndn == id:
        #nothing to do
        return apache.HTTP_NO_CONTENT
    if not ndn.endswith(db.domainID):
        return writeError(req, apache.HTTP_FORBIDDEN, "You are not allowed to change this Object. (Bad Target Domain)")
    newRDN, newPDN = ndn.split(',',1)
    oldRDN, oldPDN = id.split(',',1)
    logging.debug("move/rename %s.\n\tName: %s -> %s\n\tParent:%s -> %s" % (id, oldRDN, newRDN, oldPDN, newPDN))
    #check if this id actualy exists
    try:
        objectAttributes = db.conn.search_s(id, ldap.SCOPE_BASE)[0][1]
    except ldap.NO_SUCH_OBJECT:
        return writeError(req, apache.HTTP_NOT_FOUND, "Sorry, no such Object in your domain")
    #check renaming
    if newRDN != oldRDN:
        otype,name = newRDN.split('=')
        if not oldRDN.startswith(otype + '='):
            return writeError(req, apache.HTTP_FORBIDDEN, "You can not change the tpye of this object")
        if not re.match(r"^[a-zA-Z0-9-]+$", name):
            return apache.HTTP_FORBIDDEN
        objectAttributes[otype] = [name]
        #only allow certain types to be renamed (no hosts!)
        if len(set([t.lower() for t in objectAttributes['objectClass']]) & set(['udhostcontainer','udgroup','organizationalunit'])) == 0:
            return writeError(req, apache.HTTP_BAD_REQUEST, "You can not rename this object")
    #check if target already exists.
    try:
        db.conn.search_s(ndn, ldap.SCOPE_BASE)
        return writeError(req, apache.HTTP_FORBIDDEN, "You are not allowed to change this Object. (Target already exists)")
    except ldap.NO_SUCH_OBJECT:
        pass
    #check new parent
    if newPDN != oldPDN:
        if ndn.endswith(id):
            return writeError(req, apache.HTTP_FORBIDDEN, "Can not move this object into itself")
        try:
            parentAttributes = db.conn.search_s(newPDN, ldap.SCOPE_BASE, '(objectClass=*)', ['objectClass'])[0][1]
            if len(set([t.lower() for t in parentAttributes['objectClass']]) & set([ 'uddomain','udhostcontainer','udgroup','organizationalunit'])) == 0:
                return writeError(req, apache.HTTP_BAD_REQUEST, "Can not move. (Bad Target type)")
        except ldap.NO_SUCH_OBJECT:
            return writeError(req, apache.HTTP_FORBIDDEN, "Can not move. (new parent not existent)")
    logging.debug('moving %s to %s.' % (id,ndn))    
    modlist = ldap.modlist.addModlist(objectAttributes)
    db.conn.add_s(ndn,modlist)
    moveChildNodes(db,id, ndn)
    db.conn.delete_s(id)
    return apache.HTTP_NO_CONTENT
    
def PUT(req,id):
    """Create a new child node.
    This only is required to create ou or udGroup or udHostContainer items.
    required parameters
        type = the udtype (ou,udGroup,udHostContainer)
        name = name of the new node."""
    req.add_common_vars()
    config = UniDomain.Classes.Config(file=os.path.dirname(__file__) + '/../etc/www_conf.xml')
    domad = UniDomain.Classes.Authen(config).authenticate(ccpath=req.subprocess_env['KRB5CCNAME'])
    if not domad: # cant happen or apache auth is set up wrong.
        return writeError(req, apache.HTTP_FORBIDDEN, "Can not validate kerberos Ticket Data")
    db = UniDomain.Classes.Author(config).authorize(domad.split('@')[0])
    if not db:
        return writeError(req, apache.HTTP_FORBIDDEN, "Database Connection failed for user %s" % (req.subprocess_env['REMOTE_USER']))
    if not id.endswith(db.domainID):
        return writeError(req, apache.HTTP_FORBIDDEN, "Can not create Objects outside your domain.")
    try:
        type = urllib.unquote(req.form['type'])
        name = urllib.unquote(req.form['name'])
        #name sanitation, be strict what we allow here, only allow hostname chars from rfc 1123
        if re.match(r"^[a-zA-Z0-9-]+$", name):
            if type == 'ou':
                ndn = 'ou=%s,%s' % (name,id)
                nat = [('objectClass',['organizationalUnit'])]
            elif type == 'udGroup':
                ndn = 'cn=%s,%s' % (name,id)
                nat = [('objectClass', ['top', 'udGroup']),('description', 'a newly created udGroup Object.')]
            elif type == 'udHostContainer':
                ndn = 'ou=%s,%s' % (name,id)
                nat = [('objectClass', ['top', 'udHostContainer']),('description', 'a newly created udHostContainer Object.'), ('udGroup',['defaults'])]
            else:
                return writeError(req, apache.HTTP_FORBIDDEN, "Bad Object type specified.")
        else:
            return writeError(req, apache.HTTP_FORBIDDEN, "Sorry. Only [a-zA-Z0-9-] are allowed in object names.")
        try:
            childs = db.conn.search_s(ndn,ldap.SCOPE_BASE, attrsonly=1)
            return writeError(req, apache.HTTP_CONFLICT, "Already exists.")
        except ldap.NO_SUCH_OBJECT:
            db.conn.add_s(ndn,nat)
            return apache.HTTP_NO_CONTENT
    except KeyError:
        return writeError(req, apache.HTTP_BAD_REQUEST, "Did not look like a valid request.")
    
def DELETE(req,id):
    """Delete this Node.
    This shall only allow deletation of ou and udGroup and udHostContainer items."""
    req.add_common_vars()
    config = UniDomain.Classes.Config(file=os.path.dirname(__file__) + '/../etc/www_conf.xml')
    domad = UniDomain.Classes.Authen(config).authenticate(ccpath=req.subprocess_env['KRB5CCNAME'])
    if not domad:
        return writeError(req, apache.HTTP_FORBIDDEN, "Can not validate kerberos Ticket Data")
    db = UniDomain.Classes.Author(config).authorize(domad.split('@')[0])
    if not db:
        return writeError(req, apache.HTTP_FORBIDDEN, "Database Connection failed for user %s" % (req.subprocess_env['REMOTE_USER']))
    if not id.endswith(db.domainID):
        return apache.HTTP_FORBIDDEN
    try:
        childs = db.conn.search_s(id,ldap.SCOPE_SUBTREE,'(&(&(!(objectClass=udHostContainer))(!(objectClass=udGroup)))(!(objectClass=organizationalUnit)))', attrsonly=1)
    except ldap.NO_SUCH_OBJECT:
        return writeError(req, apache.HTTP_FORBIDDEN, "You can not delete Objects outside your domain.")
    if len(childs) > 0:
        logging.info('attempt to delete %s. Has nodeletable subchilds..' %id)
        return writeError(req, apache.HTTP_CONFLICT, "This object contains undeletable children.")
    logging.info('looks fine. going to delete %s.' % id)
    deleteTree(db,id)
    return apache.HTTP_NO_CONTENT

