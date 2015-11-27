# coding: utf-8
"""
THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
FOR LICENCE DETAILS SEE share/LICENSE.TXT

(c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
(c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>

Ldap Plugin for ud2 Client
This class provides the admin functionailty.
This file should NOT be distributed with the default ud2client, as it contains structural information about the backend.
"""

import UniDomain.plugins.ldapdb as ldapdb
import UniDomain.Classes as Classes
import ldap
import ldap.sasl
import os
import base64
import logging

class Author(Classes.Author):
    """Ldap Authorization Class"""
    def authorize(self, user):
        """Check this users authorization."""
        db = ldap_dbb(self.config, user)
        if not db.get_ldapconn():
            logging.error('Authorization to ldap-server failed.')
            return False
        self.db = db
        return db

class ldap_dbb(ldapdb.ldap_dbb):
    """Ldap database backend class for admins. some special methods in here we dont want usual domads see."""

    def update_dnsSOA(self, host):
        """housekeeping job shall update DNS SOA (time) record regulary """
        res = self.conn.search(self.config.ldapbase, ldap.SCOPE_SUBTREE, "(&(objectClass=dnsZone)(relativeDomainName=@))", ["SOARecord"])
        res = self.conn.result(res)[1]
        if len(res) > 1: 
            logging.warning('Warning: Multiple SOA records found! Using %s', res[0][0])
        SOAdn, SOArecord = res[0]
        SOArecord = SOArecord["SOARecord"][0]
        nowstr = self.nowstr()
        if SOArecord and nowstr: 
            SOArecord = SOArecord.split()
            SOArecord[2] = nowstr
            newSOA = " "
            newSOA = newSOA.join(SOArecord)
            logging.info("DNS replace \'%s\' SOARecord with : %s ", SOAdn, newSOA )
            mod_attr = [( ldap.MOD_REPLACE, 'SOARecord', newSOA )]
            return self.conn.result(self.conn.modify(SOAdn, mod_attr))
        else:
            return False
    
    def init_domain(self, domain):
        """initialise a new domain.
        domain shall be the domains name
        implementation detail. Domads actualy can create domains....inside their own domain. They should not work since we do not support nested domains (?)"""
        if self.get_itemID(domain):
            logging.warning('Domain already exists! Nothing changed.')
            return False
        logging.debug('intialising new domain %s with default values: ', domain)
        master_dn = 'ou=%s,%s' % (domain, self.config.ldapbase)
        master_domain = [
            ('objectClass', ['top', 'udDomain']),
            ('description', ['this is your base domain container']),
            ('udGroup', ['defaults']) ]
        
        server_dn = "ou=%s,%s" % ('server', master_dn)
        server = [
            ('objectClass', ['top', 'udHostContainer']), 
            ('description', 'all servers go here'), 
            ('udGroup', 'defaults') ]

        DMZ_dn = "ou=%s,%s" % ('DMZ', server_dn)
        DMZ = [
            ('objectClass', ['top', 'udHostContainer']), 
            ('description', 'DMZ hosts may have special security and compliance guidelines'),
            ('policyClass', ['DMZ']),
            ('udGroup', 'defaults') ]
            
        internal_dn = "ou=%s,%s" % ('intern', server_dn)
        internal = [
            ('objectClass', ['top', 'udHostContainer']), 
            ('description', 'internal hosts.'),
            ('policyClass', ['DMZ']),
            ('udGroup', 'defaults') ]

        workstation_dn = "ou=%s,%s" % ('workstation', master_dn)
        workstation = [
            ('objectClass', ['top', 'udHostContainer']), 
            ('description', 'all workstations and desktops below this ou'), 
            ('udGroup', 'domainDefault') ]
            
        settings_dn = "cn=%s,%s" % ('settings', master_dn)
        settings = [('objectClass', ['top'])]
        
        classes_dn = "cn=%s,%s" % ('classes', settings_dn)
        classes = [('objectClass', ['top'])]

        defaults_dn = "cn=%s,%s" % ('defaults', classes_dn)
        defaults = [
            ('objectClass', ['top', 'udGroup']),
            ('description', 'Domain defaults per URZ.'),
            ('uid', ['hoehle','gschwina','sindling']),
            ('unixGroup', ['urzwheel', 'urz']),
            ('policyClass', ['managed', 'intern', 'kerberos', 'UD.UNIBAS.CH']) ]
    
        res = [
            self.conn.add(master_dn, master_domain),
            self.conn.add(server_dn, server),
            self.conn.add(DMZ_dn, DMZ),
            self.conn.add(internal_dn, internal),
            self.conn.add(workstation_dn, workstation),
            self.conn.add(settings_dn, settings),
            self.conn.add(classes_dn, classes),
            self.conn.add(defaults_dn, defaults)]
        # wait for all writes to finish.
        for x in res:
            self.conn.result(x)
        logging.debug('done\n')
        return True
        
    def list_domains(self):
        """list all domains in the db backend"""
        res = self.conn.result(self.conn.search(self.config.ldapbase, ldap.SCOPE_SUBTREE, '(objectClass=udDomain)', ['ou','description']))[1]
        return [(att['ou'][0], att['description'][0], self.norm_dn(dn)) for (dn, att) in res]
    
    #--- DOMAD admin functions for Enterprise admins.
    def add_domad(self, domain, domad, password, fullname=False):
        """add a new domain admin to a domain.
        domain shall be a domainName or ID
        domad shall be of format abc/domad
        if fullname is specified, this will be the persons sn, else we add some fake value."""
        if not domain.endswith(self.config.ldapbase):
            domain = self.get_itemID(domain)
            if not domain:
                logging.warning('can not add %s to domain %s. No such domain.\n', domad, domain)
                return False
        if not domad.endswith('/domad'):
            domad = domad + '/domad'
        #search for domad in ALL domains. Else we risk name conflicts.
        if self.get_itemID(domad, self.config.ldapbase):
            logging.warning('domad %s already exists. Not changing', domad)
            return False
        domad_dn = "uid=%s,%s" % (domad, domain)
        try:
            import sha
            salt = os.urandom(4)
            h = sha.new(password)
            h.update(salt)
            pw = "{SSHA}" + base64.b64encode(h.digest() + salt)
        except Exception, err:
            logging.error('Error: add_domad(): Trouble generating password hash\n\t%s\n', str(err))
            return False
        try:
            if not fullname: 
                fullname = domad + ' Domain Administrator'
            domad = [
                ('cn', domad), 
                ('objectClass', ['top', 'person', 'organizationalPerson', 'inetorgperson']), 
                ('description', 'domain administrator account to manage all systems'),     
                ('userPassword', pw),     
                ('sn', fullname) ]
            #wait for add to finish.
            self.conn.result(self.conn.add(domad_dn, domad))
        except Exception, err:
            logging.warning('add_domad(): Trouble adding to ldap\n\t%s\n', str(err) )
            return False
        logging.info('added %s to domain %s', domad, domain)
        return True
        
    def delete_domad(self, domad, domain=False):
        """delete domad from domain in the db-backend
        domain shall be a domainName or ID
        domad shall be of format abc/domad"""
        if not domain:
            domain = self.config.ldapbase
        elif not domain.endswith(self.config.ldapbase):
            domain = self.get_itemID(domain)
            if not domain:
                logging.warning('can not delete %s to from %s. No such domain.', domad, domain)
                return False
        if not domad.endswith('/domad'):
            domad = domad + '/domad'
        domad_dn = self.get_itemID(domad, domain)
        if not domad_dn:
            logging.warning('No domad named %s in %s', domad, domain)
            return False
        try:
            #wait for add to finish.
            self.conn.result(self.conn.delete(domad_dn))
        except Exception, err:
            logging.error('delete_domad(): Trouble deleting\n\t%s', str(err))
            return False
        logging.info('deleted %s from domain %s', domad, domain)
        return True
        
    def list_domad(self, domad=False, domain=False):
        """list all domads (in domain, or all)
        domad shall be of format abc/domad (lists all domads if not specified.
        domain shall be a domainName or ID (list admins from all domains if not specified)"""
        if not domain:
            domain = self.config.ldapbase
        elif not domain.endswith(self.config.ldapbase):
            domain = self.get_itemID(domain)
            if not domain:
                logging.warning('Warning: No domain named %s.', domain)
                return []
        if not domad:
            domad = '*/domad'
        elif not domad.endswith('/domad'):
            domad = domad + '/domad'
        #wait for search to finish
        res = self.conn.result(self.conn.search(domain, ldap.SCOPE_SUBTREE, '(&(objectClass=Person)(uid=%s))' % domad, ['cn', 'description','sn']))[1]
        return [(att['cn'][0], att['sn'][0], att['description'][0], self.norm_dn(dn)) for (dn, att) in res]
    
    #--- HOST admin functions for Enterprise admins.
        
    def delete_host(self, host, domain=False):
        """delete a host to a domain
        host shall be the hosts fqdn
        Domain shall be a domainName or ID"""
        if not domain:
            domain = self.domainID
        elif not domain.endswith(self.config.ldapbase):
            domain = self.get_itemID(domain)
            if not domain:
                logging.warning('can not delete %s from %s. No such domain.', host, domain)
                return False
        #FIXME: I dont like this krb5-dependancy...
        if not host.startswith('host/'): 
            host = 'host/%s' % (host)
        hostID = self.get_itemID(host, domain)
        if not hostID:
            logging.warning('No Host named %s in %s', host, domain)
            return False
        try:
            #wait for delete to finsih.
            self.conn.result(self.conn.delete(hostID))
        except Exception, err:
            logging.error('delete_host(): Trouble deleting\n\t' + str(err))
            return False
        logging.info('deleted host %s from %s', host, domain)
        return True
        
        
