import unittest
import UniDomain.Classes as Classes


#---- unittest Test Classes below here
class TestConfig(unittest.TestCase):
    """Test Config Class"""
    def test_Config(self):
        """Check if required config defaults are set"""
        self.config = Classes.Config()
        self.assertTrue('plugin_authen' in self.config.config, 'no authen plugin in default config')
        self.assertTrue('plugin_author' in self.config.config, 'no author plugin in default config')
        self.assertTrue('cachedir' in self.config.config, 'no cache directory in default config')
        self.assertTrue('policydir' in self.config.config, 'no policy directory in default config')
        self.assertTrue('dnszone' in self.config.config, 'no dnszone in default config')
        self.assertTrue('passwdfile' in self.config.config, 'no passwdfile in default config')
        self.assertTrue('groupfile' in self.config.config, 'no groupfile in default config')
    def test_readconf(self):
        """check if readconf behaves like we want"""
        self.config = Classes.Config(file = 'testconf.xml', passwdfile = 'xyz')
        self.assertEqual(len(self.config.ldapservers), 1, 'reading value from file does not work.')
        self.assertEqual(type(self.config.debug),type(True), 'debug value is not bool!')
        self.assertEqual(self.config.passwdfile, 'xyz', 'passing config vars as args doesnt work')
        
    

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestConfig)
    unittest.TextTestRunner(verbosity=2).run(suite)

