#!/usr/bin/python
import unittest
import socket
import os.path
import UniDomain.Classes as Classes
import sys
import logging
import shutil

username = False
userpw = False
krb5cc = False

class TestLogins(unittest.TestCase):
    """Test Authen Class (basic authentication test)"""
    def testdefaultAuthen(self):
        """check if default login is non-interactive and works"""
        config = Classes.Config()
        authen = Classes.Authen()
        self.assertEqual(authen.__module__, 'UniDomain.plugins.krb5_keytab')
        self.assertEqual(authen.authenticate(), 'host/' + socket.getfqdn() + '@' + config.krb5realm, 'default login with keytab failed.')
        self.assertTrue(authen.isAuthenticated , 'isAuthenticated is not set after login.')
        authen.kadmin()
        self.assertTrue(authen.kadm, 'cant acquire kadmin ticket.')
    def testPasswordAuthen(self):
        """check if password login works"""
        config = Classes.Config(plugin_authen='krb5_login')
        authen = Classes.Authen(config)
        self.assertEqual(authen.__module__, 'UniDomain.plugins.krb5_login')
        authen.authenticate(user=sys.modules['__main__'].username, pw=sys.modules['__main__'].userpw)
        self.assertTrue(authen.isAuthenticated , 'isAuthenticated is not set after login.')
        authen.kadmin()
        self.assertTrue(authen.kadm, 'cant acquire kadmin ticket.')
    def testApacheAuthen(self):
        """test if apache authen works"""
        config = Classes.Config(plugin_authen='krb5_apache')
        authen = Classes.Authen(config)
        self.assertEqual(authen.__module__, 'UniDomain.plugins.krb5_apache', 'apache laods wrong plugin')
        self.assertEqual(authen.authenticate(ccfile='FILE:' + sys.modules['__main__'].krb5cc), sys.modules['__main__'].username + '@' + config.krb5realm, 'apache_authen returns wrong username')
        self.assertTrue(authen.isAuthenticated, 'isAuthenticated is not set after login.')
        self.assertFalse(authen.kadm, 'apache authen sets kadmin. we dont have kadmin privileges')
        try:
            authen.kadmin()
            self.fail('apache plugin should not have a kadmin interface.')
        except: pass

class TestHostAdmin(unittest.TestCase):
    """Test if the host admin functionality works. partialy requires super cow privileges"""
    def setUp(self):
        self.config = Classes.Config(plugin_authen='krb5_login', krb5keytab='./keytab')
        self.authen = Classes.Authen(self.config)
        self.usid = self.authen.authenticate(user=sys.modules['__main__'].username, pw=sys.modules['__main__'].userpw)
        self.authen.kadmin()
        
    def testListHost(self):
        """Check if we correctly list existent hosts"""
        hostname = socket.getfqdn()
        usid = 'host/%s@%s' % (hostname,self.config.krb5realm)
        self.assertTrue(usid in self.authen.list_hosts(), 'Testing Host is gone.')
        self.assertEqual(self.authen.list_hosts(hostname), [usid], 'list_hosts returned wrong hostUSID for fqdn')
        self.assertEqual(self.authen.list_hosts('host/%s' % hostname), [usid], 'list_hosts returned wrong USID for this host/fqdn')
        self.assertEqual(self.authen.list_hosts(usid),[usid], 'list_hosts returned wrong USID for host/fqdn@realm')
        self.assertEqual(self.authen.list_hosts('xyz_NotExistingBadWordFuck'), [], 'list_hosts returned a nonempty list for bad host names')

    def testChangeHost(self):
        """test if adding/removing of hosts in authen works"""
        newFqdn = 'testhost' + random.randint(1000, 9999) + currentFqdn.split('.',1)[1]
        self.assertTrue(self.authen.add_host('host/' + newFqdn), 'Adding new host usid failed.')
        self.assertFalse(self.authen.add_host('host/' + newFqdn), 'Adding host again suceeded.')
        self.assertTrue(os.path.isfile('./keytab'), 'Retreiving of host keytab file failed.')
        self.assertFalse(self.authen.delete_host('host/nonExistent.' + newFqdn), 'delete of inexistent host failed.')
        self.assertTrue(self.authen.delete_host('host/' + newFqdn), 'delete of existing host account failed')
        os.unlink('./password')

        
class TestDomadAdmin(unittest.TestCase):
    """Test authen admin backend.
    This requires a admin login account"""
    def setUp(self):
        self.config = Classes.Config(plugin_authen='krb5_login', krb5keytab='./keytab')
        self.authen = Classes.Authen(self.config)
        self.usid = self.authen.authenticate(user=sys.modules['__main__'].username, pw=sys.modules['__main__'].userpw)
        self.authen.kadmin()
        self.testname = 'spahan'

    def testListDomad(self):
        """ check if listing domads works in authen"""
        testresult = self.testname + '/domad@UD.UNIBAS.CH'
        self.assertTrue(testresult in self.authen.list_domad(), 'i got fired?')
        self.assertEqual(self.authen.list_domad(self.testname), [testresult], 'list_domad returned wrong domad for spahan')
        self.assertEqual(self.authen.list_domad(self.testname + '/domad'), [testresult], 'list_domad returned wrong domad for spahan/domad')
        self.assertEqual(self.authen.list_domad(testresult), [testresult], 'list_domad returned wrong domad for spahan/domad@Ud.UNIBAS.CH')
        self.assertEqual(self.authen.list_domad('notExistent_' + self.testname), [], 'list_domad returned a nonempty list for bad domdad names.')

    def testChangeDomad(self):
        """check if host adding/removing works"""
        newDomad = self.testname + random.randint(1000, 9999)
        self.assertFalse(self.authen.add_domad(self.testname,'spahantest'), 'I got a twin')
        self.assertTrue(self.authen.add_domad(newDomad,'spahantest'), 'Cant add new domad')
        self.assertTrue(self.authen.list_domad(newDomad), 'New domad was not created.')
        self.assertFalse(self.authen.delete_domad('nonExistent' + self.testname, 'spahantest'), 'Can delete nonexistent domad...')
        self.assertTrie(Self.authen.delete_domad(newDomad,'spahantest'), 'Cant delete domad from domain')

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
    authen = Classes.Authen(Classes.Config(plugin_authen='krb5_login', plugin_author='ldapdbadmin'))
    user_id = authen.authenticate()
    if user_id:
        username = authen.user
        userpw = authen.pw
        krb5cc = authen.krb5cc
        if user_id.endswith('/admin@UD.UNIBAS.CH'):
            isAdmin = True
        else:
            isAdmin = False
            print "\nNo Enterprise Admin Account. Skipping some tests due to not be able to recover nicely"
    else:
        print "\nBad credentials. Aborting"
        sys.exit(1)
    print "\n-- Testing Authen plugin compatibility --"
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestLogins)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful(): sys.exit(1)
    print "\n-- Testing Host admin functionality. --"
    if isAdmin:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(TestHostAdmin)
    else:
        suite=unittest.defaultTestLoader.loadTestsFromName('krb5.TestHostAdmin.testListHost')
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful(): sys.exit(1)
    print "\n-- Testing Domad admin functionality. --"
    if isAdmin:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(TestDomadAdmin)
    else:
        suite=unittest.defaultTestLoader.loadTestsFromName('krb5.TestDomadAdmin.testListDomad')
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful(): sys.exit(1)
    print "-- Congratulations. All Tests for krb5 passed."
