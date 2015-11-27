# coding: utf-8
"""
THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
FOR LICENCE DETAILS SEE share/LICENSE.TXT

(c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>

Base classes for ud2 client
"""
import os
import os.path
import logging

import ConfigParser
from UniDomain.functions import get_osrelease as get_osrelease
from UniDomain.functions import getlocalhostname

class Config(object):
    """
    read and set configuration vars
    """
    def __init__(self, **args):
        """
        Open a config file
        First we set all defaults.
        Then we try read <file> and add its parameters to the config (pass file='path') to set a different file
        And finaly we add all args to the defaults (use to overwrite default and file parameters"""
        self.data = ConfigParser.SafeConfigParser({
            #krb5 authen plugin config
            "plugin_authen":"krb5_keytab",
            "krb5keytab":"/etc/krb5.keytab",
            "krb5realm":"UD.UNIBAS.CH",
            "kinitpath":"/usr/bin/kinit",
            "klistpath":"/usr/bin/klist",
            "kdestroypath":"/usr/bin/kdestroy",
            "kadminpath":"/usr/sbin/kadmin",
            #ldap author plugin config
            "plugin_author":"ldapdb",
            "ldapbase":"dc=ud,dc=unibas,dc=ch",
            "ldapauthen":"ou=authen,dc=ud,dc=unibas,dc=ch",
            "ldapservers": "titan.ud.unibas.ch,atlas.ud.unibas.ch",
            "ldapproto":"ldap",
            "ldaptimeout":"30",
            #db plugin config
            "plugin_db":"ldap",
            #various other config
            "dnszone":"ud.unibas.ch",
            "cachedir":"/var/cache/ud2",
            "policydir":"/etc/sysconfig/cfengine",
            "policyfile":"/etc/managed_classes",
            "debug":"False",
            "passwdfile":"/etc/passwd",
            "groupfile":"/etc/group"})
        self.section = 'DEFAULT'
        self.file = args.pop('file', '/etc/ud2.conf')
        if not os.path.isfile(self.file):
            self.file = '/usr/local/etc/ud2.conf' # some systems clutter the configs around
            if not os.path.isfile(self.file):
                logging.warning('Warning: Can not read from config file \'%s\'. Using \'%s\' instead', self.file, '/etc/ud2.conf')
                self.file = '/etc/ud2.conf'
        #overwrite defaults with prefs from config file.
        try:
            self.data.read(self.file)
            system, dist, rel = get_osrelease()
            if self.data.has_section('%s_%s' % (dist, rel)):
                self.section = '%s_%s' % (dist, rel)
            elif self.data.has_section(dist):
                self.section = dist
            elif self.data.has_section(system):
                self.section = system
            else:
                logging.info('No system-specific configuration found. proceeding with defaults')
        except Exception, err:
            logging.warning('Warning: A error occured while reading configuration from \'%s\'. Proceeding with defaults', self.file)
            logging.debug(str(err))
        # overwrite default&file prefs with function call.
        for param in args:
            self.data.set(self.section, param, args[param])
    
    def __getattr__(self, name):
        try:
            # need check for correct type. we later may get rid of this. use only string config values.
            if name in ['debug']:
                return self.data.getboolean(self.section, name)
            elif name in ['ldaptimeout']:
                return self.data.getint(self.section, name)
            elif name in ['ldapservers']:
                return [x.strip() for x in self.data.get(self.section, name).split(',')]
            else:
                return self.data.get(self.section, name)
        except:
            raise
    
class Authen(object):
    """ 
    The Authen Class represents the Authentication Backend

    @note: This class can't actualy be instantiated. Instead it takes the plugin_authen value from the config and returns that class.
    @note: most plugins may support only a global namespace and not a domain specific.
    
    All authen plugins need inherit from this class.
    @note: Some Methodes in this Class are supposed to be only used by enterprise admins. One may want distribute stripped down Versions of a plugin which don't expose some details
    #warning: Security by Obscurity doesnt work. However it slows down the enemy. Thats worth a little
    """
    def __new__(cls, config=None, **args):
        if not config:
            config = Config()
        authen_plugin_module = __import__('UniDomain.plugins.%s' % config.plugin_authen)
        return object.__new__(authen_plugin_module.plugins.__getattribute__(config.plugin_authen).Authen)
        
    def __init__(self, config=None, **args):
        """
        Initialise a authen object. 
        @param config: the config object to use. if not set we instantiate a default config.
        @note: Subclasses MUST support is_authenticated to flag if this user was authenticated already.
        """
        if not config: 
            config = Config(True)
        self.config = config
        self.user = False
        self.is_authenticated = False
        
    def authenticate(self, **args):
        """
        Do the actual authentication process.
        @return: self or False if authentication failed
        """
        return False
    
    def add_host(self, host=False):
        """Add a host to the authen backend"""
        return self.add_service('host', host)
        
    def delete_host(self, host=False):
        """delete a host from the authen backend"""
        return self.delete_service('host', host)
        
    def list_hosts(self, host=False):
        """list all hosts in the authen backend"""
        return self.list_service('host', host)

    def get_service_name(self, service, host):
        """
        get a name used by the authen backend for the given service/host
        @param service: string for service name. defaults to 'host'.
            if this contains /<hostname> this value is taken over all others
        @param host: fqdn for which to add a service. defaults to localhost.
        @return: a host name/principal/id/whatever used by the authen backend to identify a item.
        """
        return False

    def add_service(self, service= 'host', host= getlocalhostname()):
        """
        add a service to the authen backend
        @note: this requires additional privileges
        """
        return False

    def delete_service(self, service= 'host', host= getlocalhostname()):
        """
        delete a service from the authen backend
        @note: this requires additional privileges
        """
        return False

    def list_service(self, service = 'host', host = getlocalhostname()):
        """
        list services in the authen backend
        """
        return []

    def get_service_keytab(self, service = 'host', host = getlocalhostname(), options="", keytab=None):
        """
        get service keytab
        @param service: service to add defaults to 'host'
        @param host: the host. defaults to the local hosts name
        @param options: additional options to add (encryption params, etc)
        @param keytab: which keytab to add the principal to. defaults to /etc/krb5.keytab
        @return: True if success, False otherwise
        """
        return False
    
    def kadmin(self):
        """
        initialize the kadmin interface
        This may not be implemented for certain plugins due to not have the required permissions.
        This is a optional interface method.
        """
        return False
        
class DB(object):
    """The db class represents a connection to the db-backend in use."""
    def __new__(cls, author, **args):
        author_plugin_module = __import__('UniDomain.plugins.%s' % author.config.plugin_author)
        return object.__new__(author_plugin_module.plugins.__getattribute__(author.config.plugin_author).DB)
    
    def __init__(self, authen, **args):
        """Initialise a author object. requires a config object.
        The config is taken from the authen object
        subclasses MUST create/initialize a db object which represents a connection/interface to the backend database.
        This will be used by the db class to connect to the backend."""
        self.authen = authen
        self.config = authen.config

    def connect(self):
        """Connect to the DB and check authorization.
        @return : the users database ID or False"""
        return False

    def get_domainID(self, itemID = False):
        """ 
        Get a items udDomainID.
        Domains are host containers marking a top level for a ud object tree.
        @param itemID: the item for which we want get the domain. If not set we lookup our UserID
        @deprecated: deprecated! Do not use anymore if possible.
        """
        return None
    
    def get_containerID(self, itemID = False):
        """ 
        Get a items udHostContainer ID. Returns itself if it is a container already
        @param itemID: the item for which we want know the container. If not set we lookup our UserID
        @return: the containers ID
        """
        if not itemID:
            itemID = self.userID
        parentID = self.get_parentID(itemID)
        while parentID:
            itemID = parentID
            parentID = self.get_parentID(itemID)
        return itemID

    def get_parentID(self, itemID = False):
        """
        Get a items parent ID.
        If the item is a host container this returns False.
        @param itemID: the item we want to know the parent.
        @return return the parents Database ID or False if the item is a udHostContainer
        """
        return False
        
    def get_node_data(self, node_id):
        """
        get supported Attributes for a given id
        @param id: a itemID to get its data
        @type: string
        @return: AttributeCollection Object with all attributes.
        @rtype: UniDomain.Classes.AttributeCollection
        """
        return None
        
    def get_udGroup_data(self, group):
        """
        get ud attributes from a udGroup name.
        @param id: a udGroup  name
        @note: Due to legacy reasons, there may be multiple groups with the same name.
            This function tries to resolve the group to the closest group with the given name.
        @return: AttributeCollection Object with all attributes.
        @rtype: UniDomain.Classes.AttributeCollection
        """
        return None
        
    def get_container_data(self, container_id = False):
        """
        get supported attributes for a host container and all its metagroups.
        @param id: ad udHostContainer or udDomain id.
        @return: AttributeCollection Object with all attributes.
        @rtype: UniDomain.Classes.AttributeCollection
        """
        node = self.get_node_data(container_id)
        for group in node.reduce('udGroup'):
            logging.debug('parsing group data for %s', group)
            group_data = self.get_udGroup_data(group)
            node.add(group_data)
            for subgroup in group_data.reduce('udGroup'):
                node.add(self.get_udGroup_data(subgroup))
        return node
    
    def get_host_data(self, host_id):
        """
        get supported Attributes for a host including hostcontainer and metagroups.
        This gets the hosts data and then walks up the object tree until a host container is found
        For each node we add the attributes.
        @param host_id: a udHost id.
        @return: AttributeCollection Object with all attributes.
        @rtype: UniDomain.Classes.AttributeCollection
        """
        node = self.get_container_data(host_id)
        host_id = self.get_parentID(host_id)
        while host_id:
            node.add(self.get_container_data(host_id))
            host_id = self.get_parentID(host_id)
        return node
    
    def get_user_data(self, userlist):
        """
        get posix user attributes from ldap backend
        @param userlist: list with user ids to lookup.
        @return: list with users and supported attributes in a dict.
        """ 
        return []
        
    def get_group_data(self, grouplist):
        """
        get posix group attributes from ldap backend.
        @param grouplist: list of group names or ids to lookup.
        @return: list with groups and supported attributes in a dict.
        """
        return []
    
    def update_dnsRecord(self):
        """
        update the clienthost's IPv6 and IPv4 records in the DNS-ldap-backend ;)
        a6Record naming style is not supported anymore use AAAA instead
        """
        return False
        
    #def update_dnsSOA(self, host):
    #    """housekeeping job shall update DNS SOA (time) record regulary 
    #    THIS IS A ENTERPRISE ADMIN FUNCTION. LOW PRIVILEGED PLUGINS MAY CHOOSE TO NOT IMPLEMENT THIS"""
    #    return False
    #    
    #def init_domain(self, domain):
    #    """ intialise a new domain structur in the db-backend.
    #    THIS IS A ENTERPRISE ADMIN FUNCTION. LOW PRIVILEGED PLUGINS MAY CHOOSE TO NOT IMPLEMENT THIS"""
    #    return False
    #    
    #def list_domains(self):
    #    """list all domains in the db backend
    #    THIS IS A ENTERPRISE ADMIN FUNCTION. LOW PRIVILEGED PLUGINS MAY CHOOSE TO NOT IMPLEMENT THIS"""
    #    return []
    
    #def add_domad(self, domain, domad, password, fullname=False):
    #    """add a new domain admin to a domain in the db-backend
    #    THIS IS A ENTERPRISE ADMIN FUNCTION. LOW PRIVILEGED PLUGINS MAY CHOOSE TO NOT IMPLEMENT THIS"""
    #    return False
    #    
    #def delete_domad(self, domad, domain=False):
    #    """delete domad from domain in the db-backend
    #    THIS IS A ENTERPRISE ADMIN FUNCTION. LOW PRIVILEGED PLUGINS MAY CHOOSE TO NOT IMPLEMENT THIS"""
    #    return False
    #    
    #def list_domad(self, domad=False, domain=False):
    #    """list all domads (in domain, or all)
    #    THIS IS A ENTERPRISE ADMIN FUNCTION. LOW PRIVILEGED PLUGINS MAY CHOOSE TO NOT IMPLEMENT THIS"""
    #    return []
    
    def add_host(self, host = False, target = False, classes = [], **args):
        """Add a host to a domain
        This shall add the host to the database.
        @param host: the hostname to add. If not specified we add the local host
        @param target: location to add the host in the database.
            a database specfic ID. If not specified, we add the host to the first allowed destionation.
        @param **args: udPolicy settings to initialize the host object.
            in the form policy=(at,[vars])
        @return: True if the host was successfully added to the database, False otherwise
        """
        return False
        
    def delete_host(self, host):
        """delete a host from a domain"""
        return False
        
    def list_hosts(self, host=False):
        """list all hosts (in domain)"""
        return []

    def add_policy(self, target, type, data):
        """ add a udPolicy to a host object
        @param target: a object DN or a hosts fqdn
        @param type: policy type (eg, userPolicy, fcPolicy, etc)
        @param data: policy data as a list of tuples with (att_name, [att_values])
        @return : true on success, false otherwise
        """
        return False

    def del_policy(self, target, type, data):
        """remove attributes from a udPolicy.
        @param target: a object dn or a hosts fqdn
        @param type: type of policy (eg, userPolicy, sudoPolicy, etc)
        @param data: polica data as a list of tuples with (att_name, [att_values])
        @return: True on success, False else
        """
        return False

class AttributeCollection(object):
    """
    This Class will be assigned all data from a specific ud-object.
    
    @note: Attribute Collection Classes can  be merged. They will keep links to the origin too.
    @note: This class somewhat reverses the ldap object->attributes relation into a attributes->object relation. 
        After merging all required object (decision  logic) this then should be passed to the writer or whatever other object needs this information.
    @note: This class should be used to define all suported ldap-attributes."""
    def __init__(self):
        self.data = {"uid" : [], "unixGroup" : [], "policyClass" : [], "udGroup" : [], "objectClass" : []}
        self.policies = {}

    def __str__(self):
        return "data:%s\npolicies:%s" % (self.data, self.policies)
    
    def supported_attributes(self):
        """
        @return: all supported ldap-attributes.
        """
        return self.data.keys()
        
    def add(self, collector):
        """
        Add another AttributeCollection to this one.
        @param collector: the attributeCollector to merge with this one.
        """
        for attribute in self.data.keys():
            self.data[attribute].extend(collector.data[attribute])
        for policy in collector.policies:
            if policy in self.policies:
                self.policies[policy].extend(collector.policies[policy])
            else:
                self.policies[policy] = collector.policies[policy]
                
            
    def reduce(self, attribute):
        """
        remove all duplicates and return a object containing the requested attribute list with no source info.
        @param attribute: attribute to reduce.
        @return: returns a data object with sets instead lists
        @rtype: set
        """
        return set([item[0] for item in self.data[attribute]])
        
    def getPolicies(self):
        """returns a dictionary with all policies, each with merged attributes from all policy providers."""
        tmp = {}
        for policy in self.policies:
            tmp[policy] = {}
            for (pol_id, atts) in self.policies[policy]:
                for at in atts:
                    if not at in tmp[policy]:
                        tmp[policy][at] = set()
                    tmp[policy][at] |= set(atts[at])
        #pull in  old style policies
        if 'userPolicy' in tmp:
            #we only get 'uid' from old settings. no other attributes.
            if 'uid' in tmp['userPolicy']:
                tmp['userPolicy']['uid'] |= self.reduce('uid')
            else:
                tmp['userPolicy']['uid'] = self.reduce('uid')
        else:
            tmp['userPolicy'] = {'uid':self.reduce('uid')}
        #merge in legacy roup settings.
        if 'groupPolicy' in tmp:
            if 'unixGroup' in tmp['groupPolicy']:
                tmp['groupPolicy']['unixGroup'] |= self.reduce('unixGroup')
            else:
                tmp['groupPolicy']['unixGroup'] = self.reduce('unixGroup')
        else:
            tmp['groupPolicy'] = {'unixGroup':self.reduce('unixGroup')}
        #merge in legacy cf engine policies settings
        if 'cfPolicy' in tmp:
            if 'policyClass' in tmp['cfPolicy']:
                tmp['cfPolicy']['policyClass'] |= self.reduce('policyClass')
            else:
                tmp['cfPolicy']['policyClass'] = self.reduce('policyClass')
        else:
            tmp['cfPolicy'] = {'policyClass':self.reduce('policyClass')}
        return tmp
