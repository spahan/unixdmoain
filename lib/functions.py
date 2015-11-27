# coding: utf-8

"""

THIS SOFTWARE IS LICENSED UNDER THE BSD LICENSE CONDITIONS.
FOR LICENCE DETAILS SEE share/LICENSE.TXT

(c) 2005-2009, Marco Hoehle <marco.hoehle@unibas.ch>
(c) 2010, Hanspeter Spalinger <h.spalinger@stud.unibas.ch>


"wild" functions for ud
just because we dont know where else to place them
"""


import os
import sys
import socket
import logging
import subprocess
import re

from tempfile import mkstemp
from shutil import move

import platform

def get_osrelease():
    """
    detect the *nix* distribution based on some file tests.
    Will return 'system', 'distro', 'version'
    """
    system = platform.system()
    if system == 'Linux':
        (distro, release, sub) = platform.dist()
        if distro == 'redhat':
            release = release.split('.')[0] #report only major versions.
        elif distro == 'debian':
            release = release.split('/')[0] #report major name.
        elif distro == 'SuSE':
            release = release.split('.')[0] #report major os version only.
        elif distro == 'Ubuntu':
            release = sub # there may be incompatible Ubuntus with same 'major' number. Lets use the codename.
        else:
            distro = False
            release = False
    elif system == 'Darwin':
        (release, ver, mach) = platform.mac_ver()
        tmp = release.split('.')
        distro = tmp[0] #usualy 10 for macosx.
        release = tmp[1] #corresponds to major macosx release versions.
    elif system == 'FreeBSD':
        distro = system
        release = platform.release().split('.')[0] #report major version.
    else:
        return (False, False, False)
    return (system, distro, release)


def getlocalhostname():
    """ tend to be unsafe but fast - may need to be adopted for different distributions """
    return(socket.getfqdn(get_local_ip()))

def freplace(path, pattern, new_line):
    """ case insensitively replace all lines starting with pattern with newline."""
    tmp_handle, tmp_path = mkstemp()
    new_file = open(tmp_path, 'w')
    old_file = open(path)
    done_replace = False
    for line in old_file:
        if line.lower().startswith(pattern.lower()):
            new_file.write(new_line)
            done_replace = True
        else:
            new_file.write(line)
    new_file.close()
    os.close(tmp_handle)
    old_file.close()
    move(tmp_path, path)
    return done_replace

def frepad(path, pattern, new_line):
    """ case insensitive replace all lines starting with pattern with newline
          or add newline if no such line. """
    if not freplace(path, pattern, new_line):
        fd = open(path, 'a')
        fd.write("\n" + new_line)
        fd.close()

def set_hosts(newHost, newDN):
    """ update /etc/hosts """
    my_ip = get_local_ip()
    frepad('/etc/hosts', my_ip, "%s\t%s.%s\t%s\n" % (my_ip, newHost, newDN, newHost))

def set_hostname_redhat(newHost, newDN):
    """ update hostname for redhat like systems (config in /etc/sysconfig/network)"""
    try:
        frepad('/etc/sysconfig/network', 'hostname', "HOSTNAME=%s.%s\n" % (newHost, newDN))
        set_hosts(newHost, newDN)
        subprocess.call(['hostname', '%s.%s' % (newHost,newDN)])
    except Exception, err:
        logging.debug(err)
        return False
    # FIXME: how to change the domain name? 
    #   redhat docu says its set in /etc/hosts.
    #   how do we enforce reread of that?
    logging.info("setting hostname to %s.%s", newHost, newDN)
    return True

def set_hostname_debian(newHost, newDN):
    """ set hostname debian style (hostname in /etc/hostname)"""
    try:
        fd = open('/etc/hostname', 'w')
        fd.write("%s" % (newHost))
        fd.close()
        set_hosts(newHost, newDN)
        subprocess.call(['/etc/init.d/hostname.sh restart'])
    except Exception, err:
        return False
    logging.info("setting hostname to %s.%s", newHost, newDN)
    return True

def set_hostname_freebsd(newHost, newDN):
    """ set hostname freebsd style (hostname in rc.conf or rc.conf.local) """
    try:
        if not freplace('/etc/rc.conf', 'hostname',"hostname=%s.%s\n" % (newHost, newDN)):
            fd = open('/etc/rc.conf', 'a')
            fd.write("\nhostname=\"%s.%s\"\n" % (newHost, newDN))
            fd.close()
        set_hosts(newHost, newDN)
        subprocess.call(['hostname', '%s.%s' % (newHost,newDN)])
    except Exception, err:
        return False
    logging.info("setting hostname to %s.%s", newHost, newDN)
    return True

def set_hostname(FQDN):
    newHost, newDN = FQDN.split('.', 1)
    (system, distro, release) = get_osrelease()
    if system == 'Linux':
        if distro.lower() in ['redhat','centos']:
            if not set_hostname_redhat(newHost, newDN):
                logging.warning('Unable to set new hostname. Please set the hostname manualy BEFORE continue registering the host!!')
        elif distro.lower() in ['debian']:
            set_hostname_debian(newHost, newDN)
        else:
            logging.warning('System not supported. I dont know how to set up the hostname correctly, so you have to do that yourself BEFORE continue register the host!!')
            return False
    elif system == 'FreeBSD':
        set_hostname_freebsd(newHost, newDN)
    else:
        logging.warning('System not supported. I dont knw how to set up the hostname correctly, so you have to do that yourself BEFORE continue register the host!!')
        return False

def get_local_ip():
    """connect to google and find out the local IP through this socket connect
    that is "really" connected to an network, according to the OS
    if this does fail, the firewall is to restrictive ;-)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: 
        s.connect(("131.152.1.1", 53))
    except socket.gaierror:
        sys.stderr.write("Warning: no network connection or problem in name resolution (resolver, DNS).")
        return False
    ip, localport = s.getsockname()
    s.close()
    return ip

#TODO: return ipv6 address if global. else just ignore.
#FIXME: this is trash
def get_local_ipv6(IPv6_LINKLOCAL=True):
    """python 2.4 has not yet all the nice ipv6 adress functions like python 3.x"""
    ipv6addr = []
    excludes = ["::1"]
    if IPv6_LINKLOCAL:
        SCOPE = "Scope:"
    else:
        SCOPE = "Scope:Global"
    if socket.has_ipv6:
        raw_data = subprocess.Popen("/sbin/ifconfig", stdout=subprocess.PIPE).stdout.readlines()
        ipv6_data = [x for x in raw_data if SCOPE in x]
        if len(ipv6_data) > 0:
            ip6 = re.search("inet6 addr: ([0-9a-f:]*)/\d{2,3} %s" % (SCOPE), ipv6_data[0])
            if ip6:
                return ip6.group(1)
    return False


