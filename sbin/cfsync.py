#!/usr/bin/python2
#coding:utf-8

"""
read ud2_classes and represent as dict file
"""


import re
#We need a better tmp fir for apache or set this file correctly. Else a local user can XSS us. Especialy since we use SSO.
TARGETFILE = "/opt/UD2/wwwlib/html/ud2_classes.json"
XSLTFILE="/opt/UD2/wwwlib/html/cfPolicies.xsl"

CLASSFILE = "/var/cfengine/inputs/ud2_classes.cf"
DESCFILE = "/var/cfengine/inputs/ud2_classes.README"

def read_classes(cfile=CLASSFILE, dfile=DESCFILE): 
    policies = {}
    for line in open(CLASSFILE,"r").read().split("\n"):
        found = re.search(r"(?P<policyName>.*?)=.*FileExists\w*\(\w*/etc/sysconfig/cfengine/(?P<policyFile>.*?)\).*", line)
        if found:
            policies[found.group('policyName').strip()] = {'name': found.group('policyFile'), 'description':''}
    for line in open(DESCFILE, "r").read().split("\n"):
        found = re.search(r"(?P<policyName>.*?)=(?P<policyDescription>.*)", line)
        if found:
            if found.group('policyName').strip() in policies:
                policies[found.group('policyName').strip()]['description'] += ' ' + found.group('policyDescription').strip()
    return(policies)

def write_classes(res, tfile=TARGETFILE, DEBUG=False):
    if DEBUG: 
        for key in res:
            print "%20s - %70s" % (key, res[key])
    open(tfile, "w").write(res.__repr__())
    
    xslt = open(XSLTFILE, "w")
    xslt.write("""<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns="http://www.w3.org/1999/xhtml" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<!--just a list of all available policies. this will be included by main and then we `enable` the policies which are set. -->

<xsl:template name="availableCFPolicies">""")
    for p in res:
        print res[p]
        xslt.write("""<span style="color:red;" title="%(description)s">%(name)s </span>""" % res[p])
    
    xslt.write("""</xsl:template>
</xsl:stylesheet>
""")
    xslt.close()
        
if __name__ == "__main__":
    ud_classes = read_classes()
    write_classes(ud_classes, DEBUG=True)

