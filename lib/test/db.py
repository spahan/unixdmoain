#!/usr/bin/python
import unittest
import UniDomain.Classes as Classes
import UniDomain.writer as writer
import sys
import UniDomain.functions as funcs
import socket
import ldap
import logging

username = False
userpw = False

class TestAuthor(unittest.TestCase):
    """Test if Author plugins work"""
    def setUp(self):
        self.config = Classes.Config()
        self.authen = Classes.Authen(self.config)
        self.host_usid = self.authen.authenticate()

    def testDefaultAuthor(self):
        """check if default loads non-admin backend"""
        author = Classes.Author(self.config)
        dbconn = author.authorize(self.host_usid)
        self.assertEqual(dbconn.__module__, 'UniDomain.plugins.ldapdb', 'wrong default author plugin')
        self.assertTrue(dbconn, 'authorization failed')

    def testAdminAuthor(self):
        """Check if we can load the admin db backend"""
        self.config.plugin_author='ldapdbadmin'
        author = Classes.Author(self.config)
        dbconn = author.authorize(self.host_usid)
        self.assertEqual(dbconn.__module__, 'UniDomain.plugins.ldapdbadmin', 'wrong admin author plugin')
        self.assertTrue(dbconn, 'authorization failed')

class TestDB(unittest.TestCase):
    """Test if basic db backend works as intended."""
    domad = 'spahan'
    domad_usid = 'spahan/domad@UD.UNIBAS.CH'
    domad_dn = 'uid=spahan/domad,cn=domainAdmin,cn=domainDefault,ou=spahantest,dc=ud,dc=unibas,dc=ch'
    domain_name = 'spahantest'
    domain_dn = 'ou=spahantest,dc=ud,dc=unibas,dc=ch'
    host = 'host/spahan00.urz.unibas.ch@UD.UNIBAS.CH'
    host_dn = 'cn=spahan00,ou=server,ou=spahantest,dc=ud,dc=unibas,dc=ch'

    def setUp(self):
        self.config = Classes.Config(plugin_author='ldapdbadmin')
        #self.config = Classes.Config(krb5keytab='/root/janitor/keytab', plugin_author='ldapdbadmin')
        self.authen = Classes.Authen(self.config)
        self.author = Classes.Author(self.config)
        self.usid = self.authen.authenticate()
        self.db = self.author.authorize(self.usid)

    def testdomadIDs(self):
        """test if we get correct IDs (host,domain,container) for a domad object"""
        self.assertEqual(self.db.get_itemID(TestDB.domad + '/domad'), TestDB.domad_dn, 'get_itemID returns wrong ID for domad')
        self.assertEqual(self.db.get_domainID(TestDB.domad_dn), TestDB.domain_dn , 'get_domainID returns wrong ID for domad')
        self.assertEqual(self.db.get_containerID(TestDB.domad_dn), TestDB.domain_dn, 'domain and Container for domad should be the same')

    def testHostIDs(self):
        """Test if we get the correct IDs (host,container,domain) for a Host"""
        self.assertEqual(self.db.get_itemID(TestDB.host), TestDB.host_dn, 'db: get_itemID returns wrong id for host')
        self.assertEqual(self.db.get_domainID(TestDB.host_dn), 'ou=spahantest,dc=ud,dc=unibas,dc=ch', 'db: get_domainID returns wrong domainID for host')
        self.assertEqual(self.db.get_containerID(TestDB.host_dn), 'ou=server,ou=spahantest,dc=ud,dc=unibas,dc=ch', 'db: get_containerID returns wrong containerID for host')

    def testGet_itemIDs(self):
        """test if get_itemID returns correct values for hosts,domads,admins"""
        self.assertEqual(self.db.get_itemID(), TestDB.host_dn, 'get_itemID should return local host DN if no argument is passed')
        self.assertEqual(self.db.get_itemID(TestDB.domain_name), TestDB.domain_dn, 'get_itemID returns wrong domainID for domainname')
        self.assertFalse(self.db.get_itemID('this_should_not_exist_since_it_contains_rude_words_only_for_testing_fuck'), 'get_itemID should return False on nonexistent domain names')
        self.assertEqual(self.db.get_itemID(TestDB.domad +'/domad'), TestDB.domad_dn, 'get_itemID returns wrong personID for domad name')
        self.assertFalse(self.db.get_itemID('UsingRudeWordToMakeThisImpossibleFuck/domad'), 'get_itemID should return False on nonexisting domads')
        self.assertEqual(self.db.get_itemID(TestDB.host), TestDB.host_dn, 'get_itemID returns wrong hostID for host name')
        self.assertFalse(self.db.get_itemID('host/AnotherRudeWordNameToAvoidExitenzeFuck'), 'get_itemID should return False for nonexistent hosts')
        self.assertEqual(self.db.get_itemID('hoehle/admin'), 'uid=hoehle_l,ou=Administrators, ou=TopologyManagement, o=NetscapeRoot', 'get_itemID returns wrong personID for admin name')
        self.assertFalse(self.db.get_itemID('spahan/admin'), 'wait...awww.' )
        self.assertEqual(self.db.get_itemID(TestDB.domad + '/domad', TestDB.domain_dn), TestDB.domad_dn, 'get_itemID returns different things with opr without domain')
        self.assertFalse(self.db.get_itemID(TestDB.domad + '/domad', 'ou=iWillNeverExistDueToBadWordFuck, dc=ud,dc=unibas,dc=ch'), 'get_itemID shoudl return False for inexistent DomainIDs')

    def testHostrun(self):
        """test if get_host_data returns a correctly setup host object."""
        host_id = self.db.get_itemID(TestDB.host)
        host = self.db.get_host_data(host_id)

        self.assertEqual(host.uid, ['hoehle', 'sindling', 'spahan00'], 'got wrong users from ldap backend for host')
        self.assertEqual(host.unixGroup, ['urzwheel', 'urz'], 'got wrong groups from ldap backend for host')
        self.assertEqual(host.policyClass, ['managed', 'intern', 'kerberos', 'UD.UNIBAS.CH'], 'got wrong policy classes from ldap backend for host')
        self.assertEqual(host.policyClassDisabled, [], 'got wrong policy Class disabled from ldap backend for host')
        self.assertEqual(host.udGroup, ['domainDefault', 'domainAdmin', 'domainPolicy', 'allGroups'], 'got wrong udGroupList from ldap backend for host')
        #FIXME: add tests for ResNode Here?

class TestDBDomad(unittest.TestCase):
    """Test if domad functionality works. Requires domad credentials."""
    def setUp(self):
        self.config = Classes.Config(plugin_authen='krb5_login', plugin_author='ldapdbadmin')
        #self.config = Classes.Config(krb5keytab='/root/janitor/keytab', plugin_author='ldapdbadmin')
        self.authen = Classes.Authen(self.config)
        self.author = Classes.Author(self.config)
        self.usid = self.authen.authenticate(user=sys.modules['__main__'].username, pw=sys.modules['__main__'].userpw)
        self.db = self.author.authorize(self.usid.split('@')[0])

    def test_list_domads(self):
        """testing domad listing"""
        domainID = self.db.get_itemID('spahantest')
        self.assertTrue(len(self.db.list_domad()) > 0, 'list_domads() not working. Or all domads have been laid off')
        self.assertTrue('spahan/domad' in [x[0] for x in self.db.list_domad(domain='spahantest')], 'spahan/domad not in list of domads for spahantest (domainID)')
        self.assertTrue('spahan/domad' in [x[0] for x in self.db.list_domad(domain=domainID)], 'spahan/domad not in list of domads for spahantest (domainID)')
        self.assertTrue('spahan/domad' in [x[0] for x in self.db.list_domad('spahan')], 'wrong domad for name')
        self.assertTrue('spahan/domad' in [x[0] for x in self.db.list_domad('spahan/domad')], 'wrong domad for name')
        self.assertEqual(self.db.list_domad('xyz_NotExistingBadWordFuck'), [], 'list_domad for bad domad name returns data!')
        self.assertEqual(self.db.list_domad(domain='xyz_NotExistingBadWordFuck'), [], 'list_domad for bad domain returns data!')

    def test_change_domads(self):
        """tes if add/delete of domad works"""
        myDom = self.db.get_domainID(self.db.get_itemID())
        self.assertTrue(self.db.add_domad(myDom, 'spahan01', 'hulij', 'spahan Test Account'), 'add domad to db failed')
        self.assertFalse(self.db.add_domad(myDom, 'spahan01', 'hulij', 'spahan Test Account'), 'add domad twice succeeded.')
        self.assertTrue(self.db.delete_domad('spahan01', myDom), 'delete domad failed')
        self.assertFalse(self.db.delete_domad('spahan01', myDom), 'deleting of nonexistent domad succeeded.')

    def test_list_domains(self):
        """Test if we can list domains"""
        myDom = self.db.get_domainID(self.db.get_itemID())
        self.assertTrue(len(filter(lambda x: x[2] ==myDom, self.db.list_domains())) > 0, 'list_domains does not contain this hosts domain.')
        

    def test_host_reg(self):
        """ check if we can add and delete hosts."""
        nextSerial = self.db.next_udSerial()
        self.assertTrue(nextSerial, 'cant get a free udSerial')
        self.assertFalse(self.db.add_host('xyz_NotExistingBadWordFuck'), '!!!!I addwd this host to a nonexistent domain....run check ldap-server before someone important sees it.')
        self.assertFalse(self.db.add_host('spahantest'), 'adding this host again succeeded.')
        myname, mydomain = socket.getfqdn().split('.',1)
        try:
            funcs.set_newHostname('sp.' + mydomain)
            self.assertFalse(self.db.add_host('spahantest'), 'adding short host suceeded')
            funcs.set_newHostname('spahan01.' + mydomain)
            self.assertTrue(self.db.add_host('spahantest'), 'adding new host to domain failed.')
            host_id = self.db.get_itemID()
            self.assertTrue(host_id, 'hostreg: cant get host_ID of newly created host.')
            host_dn,hostatts = self.db.conn.search_s(host_id, ldap.SCOPE_BASE)[0]
            self.assertEqual(hostatts['FQDN'], ['spahan01.' + mydomain], 'hostreg: Bad FQDN value')
            self.assertEqual(hostatts['cn'], ['spahan01'], 'hostreg: Bad cn value')
            self.assertEqual(hostatts['udSerial'], [str(nextSerial)], 'hostreg: Bad udSerial value')
            self.assertTrue('lastSeen' in hostatts, 'hostreg: missing lastSeen value.')
            self.assertEqual(sorted(hostatts['objectClass']), sorted(['top', 'dNSZone', 'udHost']), 'hostreg: Bad objectClass Attribute values.')
            self.assertEqual(hostatts['relativeDomainName'], ['spahan01'], 'hostreg: Bad relativeDomainName value')
            self.assertEqual(hostatts['zoneName'], ['ud.unibas.ch'], 'hostreg: Bad zoneName value')
            self.assertEqual(hostatts['ARecord'], [funcs.get_local_ip()], 'hostreg: Wrong ARecord value')
            self.assertEqual(hostatts['description'], ['new registered host object'], 'wrong default description')
            self.assertEqual(hostatts['dNSClass'], ['IN'], 'hostreg: wrong DNSClass')
            self.assertEqual(hostatts['dNSTTL'], ['3600'], 'hostreg: wrong dns-ttl value')
            self.assertEqual(hostatts['USID'], ['host/spahan01.%s@UD.UNIBAS.CH' % (mydomain)], 'hostreg: wrong USID value')
            self.assertEqual(self.db.next_udSerial(), nextSerial + 1, 'next udSerial is not next serial.')
            self.assertFalse(self.db.delete_host('spahan02.' + mydomain), 'delete fo inexistent host suceeded.')
            self.assertFalse(self.db.delete_host('spahan01.' + mydomain, 'spahannotExstenta'), 'delete fo host in inexistent domain suceeded.')
            self.assertTrue(self.db.delete_host('spahan01.' + mydomain), 'delete of host failed.')
            self.assertRaises(ldap.NO_SUCH_OBJECT, self.db.conn.search_s, host_id, ldap.SCOPE_BASE)
            self.assertEqual(self.db.next_udSerial(), nextSerial, 'next udSerial does not reset after delete of hostItem')
            funcs.set_newHostname('%s.%s' % (myname,mydomain))
        except:
            #FIXME: doesnt work?
            funcs.set_newHostname('%s.%s' % (myname,mydomain))
            raise
    
    def test_init_domain(self):
        """Test if we can initialise a domain structure in the ldap.
        This will run inside the authenticated users domain."""
        self.assertFalse(self.db.init_domain('spahantest'), 'init of already existing domain failed.')
        self.assertTrue(self.db.init_domain('testdomain'), 'init domain failed')
        domain_id=self.db.get_itemID('testdomain')
        self.assertTrue(domain_id, 'domini: cant get domainID of newly created domain')
        dn,atts = self.db.conn.search_s(domain_id, ldap.SCOPE_BASE)[0]
        
        self.assertEqual(atts['description'], ['this is your base domain container'], 'domini: wrong default description for domain')
        self.assertEqual(sorted(atts['objectClass']), sorted(['top', 'udDomain']), 'domini: wrong objectClasses for domain')
        self.assertEqual(atts['udGroup'], ['domainDefault'], 'domini: wrong default metagroup for domain')
        self.assertEqual(atts['ou'], ['testdomain'], 'domini: wrong domain common name.')
        res = self.db.conn.search_s(domain_id, ldap.SCOPE_SUBTREE)
        data = {}
        for (dn,at) in res: data[dn.split(',',1)[0]] = at
        self.assertTrue('ou=DMZ' in data, 'domini: no DMZ host container in domain')
        self.assertEqual(data['ou=DMZ']['udGroup'], ['domainDefault'], 'domini: wrong default metagroup for DMZ')
        self.assertEqual(data['ou=DMZ']['policyClass'], ['DMZ'], 'domini: wrong policy Class for DMZ')
        self.assertEqual(data['ou=DMZ']['description'], ['DMZ hosts may have special security and compliance guidelines'], 'domini: wrong default description for DMZ')
        self.assertEqual(data['ou=DMZ']['ou'], ['DMZ'], 'domini wrong ou name for DMZ')
        self.assertEqual(sorted(data['ou=DMZ']['objectClass']), sorted(['top','udHostContainer']), 'domini: wrong objectClasses for DMZ')
        self.assertTrue('ou=expiredHosts' in data, 'domini: no expiredHosts container in domain')
        self.assertEqual(data['ou=expiredHosts']['udGroup'], ['domainDefault'], 'domini: wrong default metagroup for expiredHosts')
        self.assertEqual(data['ou=expiredHosts']['description'], ['hosts that have not connected to the directory for a long time are considered as expired and go into this container'], 'domini: wrong default description for expiredHosts')
        self.assertEqual(data['ou=expiredHosts']['ou'], ['expiredHosts'], 'domini wrong ou name for expiredHosts')
        self.assertEqual(sorted(data['ou=expiredHosts']['objectClass']), sorted(['top','udHostContainer']), 'domini: wrong objectClasses for expiredHosts')
        self.assertTrue('ou=secureHosts' in data, 'domini: no securedosts host container in domain')
        self.assertEqual(data['ou=secureHosts']['description'], ['keep your secured hosts in this container'], 'domini: wrong default description for secureHosts')
        self.assertEqual(data['ou=secureHosts']['ou'], ['secureHosts'], 'domini wrong ou name for secureHosts')
        self.assertEqual(sorted(data['ou=secureHosts']['objectClass']), sorted(['top','udHostContainer']), 'domini: wrong objectClasses for secureHosts')
        self.assertTrue('ou=server' in data, 'domini: no server host container in domain')
        self.assertEqual(data['ou=server']['udGroup'], ['domainDefault'], 'domini: wrong default metagroup for server')
        self.assertEqual(data['ou=server']['description'], ['all servers go here'], 'domini: wrong default description for server')
        self.assertEqual(data['ou=server']['ou'], ['server'], 'domini wrong ou name for server')
        self.assertEqual(sorted(data['ou=server']['objectClass']), sorted(['top','udHostContainer']), 'domini: wrong objectClasses for server')
        self.assertTrue('ou=workstation' in data, 'domini: no workstation host container in domain')
        self.assertEqual(data['ou=workstation']['udGroup'], ['domainDefault'], 'domini: wrong default metagroup for workstation')
        self.assertEqual(data['ou=workstation']['description'], ['all workstations and desktops below this ou'], 'domini: wrong default description for workstation')
        self.assertEqual(data['ou=workstation']['ou'], ['workstation'], 'domini wrong ou name for workstation')
        self.assertEqual(sorted(data['ou=workstation']['objectClass']), sorted(['top','udHostContainer']), 'domini: wrong objectClasses for workstation')
        self.assertTrue('cn=domainDefault' in data, 'domini: no domain default group in domain')
        self.assertEqual(data['cn=domainDefault']['description'], ['meta-group to bind domain-default settings in one group'], 'domini: wrong default description for domainDefault')
        self.assertEqual(data['cn=domainDefault']['cn'], ['domainDefault'], 'domini wrong cn name for domainDefault')
        self.assertEqual(sorted(data['cn=domainDefault']['objectClass']), sorted(['top','udGroup']), 'domini: wrong objectClasses for domainDefault')
        self.assertEqual(sorted(data['cn=domainDefault']['udGroup']), sorted(['allGroups','domainAdmin','domainPolicy']), 'domini: wrong udGroup List for domainDefault')
        self.assertTrue('cn=allGroups' in data, 'domini: no allGroups group in domain.')
        self.assertEqual(data['cn=allGroups']['description'], ['here you can keep a list of all posixGroups in the domain, to avoid silly questions apply this one to all udHostContainers ;) '], 'domini: wrong default description for allGroups')
        self.assertEqual(data['cn=allGroups']['cn'], ['allGroups'], 'wrong cn value for allGroups')
        self.assertEqual(sorted(data['cn=allGroups']['objectClass']), sorted(['top','udGroup']), 'wrong objectClass for allGroups')
        self.assertEqual(sorted(data['cn=allGroups']['unixGroup']), sorted(['urz','urzwheel']), 'wrong default posixGroups')
        self.assertTrue('cn=allUsers' in data, 'domini: no AllUsers group in domain.')
        self.assertEqual(data['cn=allUsers']['description'], ['here you can keep a list of all domain users that can be used for example in combination with access to public login servers'], 'domini: wrong default desciption')
        self.assertEqual(data['cn=allUsers']['cn'], ['allUsers'], 'domini: wrong cn value for allUsers')
        self.assertEqual(data['cn=allUsers']['unixGroup'], ['urzwheel'], 'domini: wrong unixGroup value for allUsers')
        self.assertEqual(sorted(data['cn=allUsers']['objectClass']), sorted(['top','udGroup']), 'domini: wrong objectClass value for allUsers')
        self.assertEqual(sorted(data['cn=allUsers']['uid']), sorted(['gschwina','hoehle','rauan','sindling']), 'wrong default uid list for allUsers')
        self.assertTrue('cn=domainAdmin' in data, 'domini: no domainAdmin group in domain.')
        self.assertEqual(data['cn=domainAdmin']['description'], ['system administrator uids for this domain, they are per default on all systems'], 'domini: wrong default desciption for domainAdmin')
        self.assertEqual(data['cn=domainAdmin']['cn'], ['domainAdmin'], 'domini: wrong cn value for domainAdmin')
        self.assertEqual(data['cn=domainAdmin']['unixGroup'], ['urzwheel'], 'domini: wrong unixGroup value for domainAdmin')
        self.assertEqual(sorted(data['cn=domainAdmin']['objectClass']), sorted(['top','udGroup']), 'domini: wrong objectClass value for domainAdmin')
        self.assertEqual(sorted(data['cn=domainAdmin']['uid']), sorted(['gschwina','hoehle','sindling']), 'wrong default uid list for domainAdmin')
        self.assertTrue('cn=domainPolicy' in data, 'domini: no domainPolicy group in domain.')
        self.assertEqual(data['cn=domainPolicy']['description'], ['some basic policy engine classes that you want to have set on all systems'], 'domini: wrong default desciption for domainPolicy')
        self.assertEqual(data['cn=domainPolicy']['cn'], ['domainPolicy'], 'domini: wrong cn value for domainPolicy')
        self.assertEqual(sorted(data['cn=domainPolicy']['objectClass']), sorted(['top','udGroup']), 'domini: wrong objectClass value for domainPolicy')
        self.assertEqual(sorted(data['cn=domainPolicy']['policyClass']), sorted(['intern','kerberos','managed','UD.UNIBAS.CH']), 'domini wrong default policies set for policyClass')
        
        def delChilds(id):
            childs = self.db.conn.search_s(id,ldap.SCOPE_ONELEVEL, '(objectClass=*)', ['hasSubordinates'])
            for (dn,at) in childs:
                if at['hasSubordinates'] == ['TRUE']:
                    delChilds(dn)
                self.db.conn.delete_s(dn)
        delChilds(domain_id)
        self.db.conn.delete_s(domain_id)



if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == '-d':
            logging.basicConfig(level=logging.DEBUG)
        elif sys.argv[1] == '-q':
            logging.basicConfig(level=logging.CRITICAL)
        else:
            logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.ERROR)
    print "\n-- Testing Author plugin compatibility --"
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(TestAuthor)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful(): sys.exit(1)
    print "\n-- Testing Basic db backend functionality. --"
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(TestDB)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful(): sys.exit(1)
    authen = Classes.Authen(Classes.Config(plugin_authen='krb5_login', plugin_author='ldapdbadmin'))
    if not authen.authenticate():
        print "\nadmin functionality check skipped."
        sys.exit(0)
    print "\n-- Testing admin functionality --"
    username = authen.user
    userpw = authen.pw
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(TestDBDomad)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful(): sys.exit(1)
    print "-- Congratulations. All Tests for db passed."

