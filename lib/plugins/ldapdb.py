# coding: utf-8
"""

THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
FOR LICENCE DETAILS SEE share/LICENSE.TXT

(c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
(c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>

Ldap Plugin for ud2 Client
This class proveds ldap authorization and a ldap db backend

Required Configuration Values:
	- ldapservers: a list of ldap servers available. Using Round-Robin to choose one.
"""
import UniDomain.Classes as Classes
import UniDomain.functions as func
import ldap
import ldap.sasl
import random
import logging
import re
from datetime import datetime

supported_attributes = ["uid", "unixGroup", "policyClass", "udGroup", "policyClassDisabled", "uidNumber", "gidNumber", "udMemberSerial", "udMemberContainer"]
posixUser_attributes = [ "uid", "uidNumber", "gidNumber", "homeDirectory", "loginShell", "gecos" ]
posixGroup_attributes = [ "cn", "gidNumber", "memberUid" ]
supported_policies = [ 'cfPolicy', 'groupPolicy', 'localHomePolicy', 'sudoPolicy', 'userPolicy']

class DB(Classes.DB):
    """
    Ldap database backend class. 
    @see: L{UniDomain.Classes.db}
    """
    
    def __init__(self, authen):
        Classes.DB.__init__(self, authen)
        self.server = False
        self.conn = False
        self.userID = False
        self.home = []
        
    def __del__(self):
        try: 
            self.conn.unbind()
        except: 
            pass

    #### public functions from here. required by Classes.authen.

    def connect(self):
        """ open a ldap connection.
        The server is choosen with round-robin (eg, at random).
        All servers in the config list ldapservers will be tried, if none is available, db creation fails fails. 
        On success we save the connection in self.conn and the servername in self.server
        Returns itself or False"""
        servers = list(self.config.ldapservers) # copy! ldap server list so we can edit it
        auth_tokens = ldap.sasl.gssapi()
        while len(servers) > 0:
            testserv = servers.pop(random.randint(0, len(servers)-1))
            try:
                conn = ldap.initialize('%s://%s' %(self.config.ldapproto, testserv))
                if conn.sasl_interactive_bind_s('', auth_tokens) == 0:
                    self.server = testserv
                    self.conn = conn
                    if self.parse_identity():
                        logging.debug('found UID %s', self.userID)
                        return self
                    else:
                        logging.critical("can't get a valid userID from this ldap server. Trying next one.")
            except ldap.LDAPError, err:
                logging.debug('%s not reachable. Trying next server\n %s', testserv, err)
        logging.critical("all ldap servers are unreachable ! please check your configuration or environment. AFTER that kick your network admin.")
        return False
    
    def get_domainID(self, itemID = False):
        """
        @see: UniDomain.Classes.db#get_domanID
        """
        if not itemID:
            itemID = self.userID
        while not itemID == self.config.ldapbase:
            try:
                return norm_dn(self.udBase(itemID, '(objectClass=udDomain)')[0][0])
            except:
                itemID = pardn(itemID)
        logging.debug('no domain found for %s, using %s', itemID, self.config.ldapbase)
        return self.config.ldapbase

    def get_parentID(self, itemID = False):
        """
        @see: UniDomain.Classes.db#get_containerID
        """
        if not itemID:
            itemID = self.userID
        if len(self.udBase(itemID, '(|(objectClass=udHostContainer)(objectClass=udDomain))')) > 0:
            return False
        return pardn(itemID)
        
    def get_node_data(self, node_id):
        """
        @see UniDomain.Classes.db#get_node_data
        """
        node = Classes.AttributeCollection()
        ldap_result = self.udBase(node_id, '(objectClass=*)', node.supported_attributes())
        if len(ldap_result) > 0:
            if len(ldap_result) > 1: #since we search for DNs this never should happen.
                logging.warning('multiple records found for %s, using %s.', node_id, ldap_result[0][0])
            ats = ldap_result[0][1]
            for at in ats.keys():
                node.data[at] = [(val, norm_dn(node_id)) for val in ats[at]]
            #load policies for this node.
            ldap_result = self.conn.search_s(node_id, ldap.SCOPE_ONELEVEL, '(objectClass=udPolicy)')
            for policy in ldap_result:
                logging.debug('----policy is %s', policy)
                policyName = policy[0].split(',')[0].split('=')[1].strip()
                node.policies[policyName] = [(norm_dn(policy[0]), policy[1])]
                logging.debug('---- now is %s', node.policies[policyName])
        else:
            logging.error('no node data for dn %s.', node_id)
        return node
    
    def get_udGroup_data(self, group):
        """load data of a udGroup and its metagroups."""
        mydn = set(self.userID.split(',')) # sets have the & operator to find interesctions.
        query = self.udSub('(&(objectClass=udGroup)(cn=%s))' % group)
        groups = [
            (
                dn, 
                len(set(norm_dn(dn).split(',')) & mydn) #match common path parts to user dn
            ) 
            for dn,atts in self.conn.result(query)[1]
        ]
        if len(groups) == 0:
            logging.warning('no such udGroup %s', group)
            return Classes.AttributeCollection()
        groups.sort(key=lambda x:x[1], reverse=True) # longest matching path wins
        logging.debug('using %s for group name %s', groups[0][0], group)
        node = self.get_node_data(groups[0][0])
        return node
        
    def get_user_data(self, userlist):
        """
        @see UniDomain.Classes.db#get_user_data
        """
        queries = [
            self.authSub('(&(objectClass=posixAccount)(uid=%s))' % uid.strip(), posixUser_attributes) 
            for uid in userlist
        ]
        # sniff, such a nice comprehension....but python24 does not know dict comprehension :-(
        #print [
        #    {a:u[0][1][a][0] for a in u[0][1].keys()} 
        #    for r in users 
        #    for u in [self.conn.result(r)[1]] 
        #    if len(u) == 1]
        return [
            dict([(at,users[0][1][at][0]) for at in users[0][1].keys()]) 
            for result in queries
            for users in [self.conn.result(result)[1]] 
            if len(users) == 1
        ]

    def get_group_data(self, grouplist):
        """
        @see UniDomain.Classes.db#get_group_data
        """
        queries = [
            self.authSub(
                '(&(objectClass=posixGroup)(|(cn=%s)(gidNumber=%s)))' % (gid.strip(),gid.strip()), 
                ['member', 'objectClass'] + posixGroup_attributes
            ) 
            for gid in grouplist
        ]
        return [
            {   'cn':groups[0][1]['cn'][0], #ONE cn allowed
                'gidNumber':groups[0][1]['gidNumber'][0],  # ONE gidNumber allowed
                'memberUid':groups[0][1].get('memberUid', []) # none or multiple memebrUids
            }
            for result in queries
            for groups in [self.conn.result(result)[1]] 
            if len(groups) == 1
        ]

    def get_group_data_by_id(self, idList):
        """deprecated call to get group data from group id. use get_group_data instead"""
        return self.get_group_data(idList)
    
    def update_dnsRecord(self): 
        """
        update the clienthost's IPv6 and IPv4 records in the DNS-ldap-backend ;)
       
        got modify example from:
        http://www.packtpub.com/article/python-ldap-applications-more-ldap-operations-and-the-ldap-url-library
        thanks.
        """
        logging.debug("writing AAAA, lastSeen and A record for%s back to DNS.", self.userID)
        ip = func.get_local_ip()
        ipv6 = func.get_local_ipv6()
        time = nowstr()
        if not ip:
            logging.error('Host has no ip')
            return False
        if not ipv6:
            #logging.warning('Host has no ipv6.')
            #return False
            logging.info('Host has no ipv6')
        if not time:
            logging.error('Host has no clock')
            return False
       	#removed till ipv6 is deployed.
        #mod_attr = [( ldap.MOD_REPLACE, 'aAAARecord', ipv6 ),
        mod_attr = [( ldap.MOD_REPLACE, 'aRecord', ip),
                    ( ldap.MOD_REPLACE, 'lastSeen', time )]
        try:
            return self.conn.modify_s(self.userID, mod_attr)
        except ldap.INSUFFICIENT_ACCESS:
            logging.critical("%s HAS INSUFFICIENT_ACCESS (write) to ldap directory server, please contact the URZ about this issue !", self.userID )
            return False
        logging.info('updated DNS record for %s', self.userID)
        return True

    def add_host(self, hostname = None, target = None, classes = None, **args):
        """
        @see UniDomain.Classes.db#add_host
        """
        # some prechecks
        if not classes: classes = []
        if not target: target = self.home[0]
        if not hostname: hostname = func.getlocalhostname()
        shortname = hostname.split('.')[0]
        if len(self.home) == 0:
            logging.warning('%s does not have enough rights to add hosts to the database', self.userID)
            return False

        # setup host object
        host_dn = 'cn=%s,%s' % (shortname, target) # we use first home dn as target container
        #FIXME: I dont like this krb5-dependancy...
        host_usid = 'host/%s@%s' % (hostname, self.config.krb5realm)
        logging.debug('using %s as usid', host_usid)
        if len(self.list_hosts(hostname)) > 0:
            logging.warning('Host %s already exists. Not changing.', hostname)
            return True
        logging.debug('Looks good. Adding %s to %s', hostname, target)
        host_data = [
            ('cn', shortname),
            ('udSerial', '%i' % self.next_udSerial()),
            ('lastSeen', nowstr()),
            ('objectClass', ['top', 'dNSZone', 'udHost']),
            ('relativeDomainName', shortname),
            ('zoneName', self.config.dnszone),
            ('dNSTTL', '3600'),
            ('dNSClass', 'IN'),
            ('ARecord', func.get_local_ip()),
            ('FQDN', hostname),
            ('USID', host_usid),
            ('description', 'new registered host object'),
        ]
        ipv6 = func.get_local_ipv6()
        if ipv6:
            host_data.append(('aAAARecord', ipv6))
        if len(classes) > 0:
            host_data.append(('udGroup', classes))
        try:
            self.conn.result(self.conn.add(host_dn, host_data))
            # add policies
            queries = [
                self.conn.add(
                    'cn=%s,%s' % (policy, host_dn), 
                    [('objectClass', ['top','udPolicy']),args[policy]]
                )  
                for policy in args
            ]
            [
                self.conn.result(query)   
                for query in queries
            ]
        except Exception, err:
            logging.warning('add_host(): Trouble adding to ldap.\n%s', str(err))
            return False
        logging.info('added host %s to %s', hostname, target)
        return True

    def list_hosts(self, host=False):
        """
        @see UniDomain.Classes.db#list_hosts
        """
        if host:
            query = self.udSub('(&(objectClass=udHost)(|(cn=%s)(usid=host/%s@%s)))' % (host, host, self.config.krb5realm), ['cn', 'FQDN', 'USID', 'description'])
        else:
            query = self.udSub('(objectClass=udHost)', ['cn', 'FQDN', 'USID', 'description'])
        return [
            (
                att['cn'][0], # ONE cn allowed
                att['FQDN'][0], # ONE FQDN allowed
                att['USID'][0], # ONE USID allowed
                att['description'], # can have multiple or no description 
                norm_dn(dn)
            )
            for dn,att in self.conn.result(query)[1]
        ]

    def add_policy(self, target, ltype, data):
        """ add a udPolicy to a host object
        @param target: a object DN or a hosts fqdn
        @param ltype: policy type (eg, userPolicy, fcPolicy, etc)
        @param data: policy data as a list of tuples with (att_name, [att_values])
        @return : true on success, false otherwise
        """
        if not ltype in supported_policies:
            logging.warn('unknown policy type %s', ltype)
            return False
        try:
            self.conn.search_s(target, ldap.SCOPE_BASE, '(objectClass=*)', ['cn'])
        except ldap.NO_SUCH_OBJECT, e:
            try: 
                target = self.conn.search_s(self.config.ldapbase, ldap.SCOPE_SUBTREE, '(FQDN=%s)' % target)[0][0]
            except Exception, e:
                logging.warn('can not get target object %s. Error was %s', target, e)
                return False
        try:
            self.conn.search_s('cn=%s,%s' % (ltype, target), ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT, e:
            logging.debug('adding cn=%s,%s', ltype, target)
            self.conn.add_s('cn=%s,%s' % (ltype, target), [('objectClass', ['top','udPolicy'])])
        for at, vas in data:
            for va in vas:
                try:
                    logging.debug('adding %s=%s to cn=%s,%s', at, va, ltype, target)
                    self.conn.modify_s('cn=%s,%s' % (ltype, target), [(ldap.MOD_ADD, at, va)])
                except ldap.TYPE_OR_VALUE_EXISTS, e:
                    logging.debug('%s already in %s for cn=%s,%s', va, at, ltype, target)
        return True

    def del_policy(self, target, ltype, data):
        """remove attributes from a udPolicy.
        @param target: a object dn or a hosts fqdn
        @param ltype: type of policy (eg, userPolicy, sudoPolicy, etc)
        @param data: polica data as a list of tuples with (att_name, [att_values])
        @return: True on success, False else
        """
        try:
            self.conn.search_s(target, ldap.SCOPE_BASE, '(objectClass=*)', ['cn'])
        except ldap.NO_SUCH_OBJECT, e:
            try:
                target = self.conn.search_s(self.config.ldapbase, ldap.SCOPE_SUBTREE, '(FQDN=%s)' % target)[0][0]
            except Exception, e:
                logging.warn('can not get target object %s. Error was %s', target, e)
                return False
        try:
            self.conn.search_s('cn=%s,%s' % (ltype, target), ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT, e:
            logging.debug('no policy object %s in %s. Nothing to do', ltype, target)
            return True
        for at, vas in data:
            for va in vas:
                try:
                    logging.debug('removing %s=%s from to cn=%s,%s', at, va, ltype, target)
                    self.conn.modify_s('cn=%s,%s' % (ltype, target), [(ldap.MOD_DELETE, at, va)])
                except ldap.NO_SUCH_ATTRIBUTE, e:
                    logging.debug ('%s=%s not in cn=%s,%s', at, va, type, target)
        # remove the policy object if no more attributes are set
        if len(self.conn.search_s('cn=%s,%s' % (ltype, target), ldap.SCOPE_BASE, '(objectClass=udPolicy)', ['uid', 'unixGroup', 'disabledPolicyData', 'policyPath', 'customPolicyData'])[0][1]) == 0:
            self.conn.delete_s('cn=%s,%s' % (ltype, target))
        return True

    def list_policies(self, target, ltype=False):
        """list policies of type type (or all if type is not specified
        @param target: a object dn or a hosts fqdn
        @param ltype: list of policy types to list (List all if False)
        @return: { ltype: (att, [vals]) }, or False
        """
        if not ltype: ltype = supported_policies
        try:
            self.conn.search_s(target, ldap.SCOPE_BASE, '(objectClass=*)', ['cn'])
        except ldap.NO_SUCH_OBJECT, e:
            try:
                target = self.conn.search_s(self.config.ldapbase, ldap.SCOPE_SUBTREE, '(FQDN=%s)' % target)[0][0]
            except Exception, e:
                logging.warn('can not get target object %s. Error was %s', target, e)
                return False
        result = {}
        for pol in type:
            try:
                result[pol] = self.conn.search_s('cn=%s,%s' % (pol, target), ldap.SCOPE_BASE, '(objectClass=udPolicy)')[0]
            except Exception, e:
                logging.debug('got exception %s while listing policies', e)
        return result

    #### private ldap backend functions from here.

    def parse_identity(self):
        """get users dn (self.userID) and home 
        home is a array of dns we are allowed to write to.
        the first dn in homes will be used to place hosts into by default."""
        try:
            logging.debug('using ldap filter (|(uid=%s)(USID=%s@%s))', self.authen.user, self.authen.user, self.config.krb5realm)
            self.userID = norm_dn(self.conn.search_s(self.config.ldapbase, ldap.SCOPE_SUBTREE, '(|(uid=%s)(USID=%s@%s))' % (self.authen.user, self.authen.user, self.config.krb5realm), ['dn'])[0][0])
        except Exception, e:
            logging.warning('No user ID found for %s.', self.authen.user)
            return False
        logging.info('found ldap dn %s for uid %s', self.userID, self.authen.user)
        
        try:
            target_pattern = re.compile(r'\(targetattr = "\*"\) \(target = "ldap:///([^"]*)".*;allow \(all\).*userdn\s*=\s*"ldap:///uid=%s\s*,' % self.authen.user)
            query = self.udSub('(&(objectClass=udDomain)(aci=*%s*))' % (self.authen.user), ['aci'])
            # we have to normalize the dn's for comparing
            #print [attributes for dn,attributes in self.conn.result(query)[1]]
            self.home = [
                norm_dn(match.group(1))
                for dn, attributes in self.conn.result(query)[1]
                for aci in attributes['aci']
                for match in [target_pattern.match(aci)] if match
            ]
        except Exception, e:
            logging.debug(e)
        logging.debug('found home %s', self.home)
        return True

    def next_udSerial(self):
        """search for the highest udSerial nubmer and return +1"""
        query = self.udSub("(objectClass=udHost)", ['udSerial'])
        return max([
            int(atts['udSerial'][-1], 10)
            for dn,atts in self.conn.result(query)[1]
        ])

    #### convinience functions
    def udSub(self, lfilter='(objectClass=*)', attributes=None):
        """ldap search in base for scope SUB"""
        if not attributes: attributes = ['dn']
        return self.conn.search(self.config.ldapbase, ldap.SCOPE_SUBTREE, lfilter, attributes)
    def udBase(self, dn, lfilter='(objectClass=*)', attributes=None):
        """ldap search_s in base for Scope BASE"""
        if not attributes: attributes = ['dn']
        return self.conn.search_s(dn, ldap.SCOPE_BASE, lfilter, attributes)
    def authSub(self, lfilter='(objectClass=*)', attributes=None):
        """ldap search in authen for scope SUB"""
        if not attributes: attributes = ['dn']
        return self.conn.search(self.config.ldapauthen, ldap.SCOPE_SUBTREE, lfilter, attributes)

# some static helpers
def pardn(dn):
    """return the parent dn"""
    return dn.split(',', 1)[1]

def nowstr():
    """create a time string for ldap"""
    return datetime.now().strftime("1%y%m%d%H")
        
#remove whitespace from dn separator.
def norm_dn(dn):
    """normalize a dn according to RFC 2253, 
    append this to all DNs from the ldap server and from other external input.
    This does NOT escape the string!"""
    return ','.join(['%s=%s' % (t, v) for (t, v) in [re.split('\s*[=]\s*', tmp) for tmp in re.split('\s*[,;]\s*', dn.strip())]])
