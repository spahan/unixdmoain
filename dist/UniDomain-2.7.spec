# - - Preamble - -
Summary: University Domain Basel
Name: UniDomain
Version: 2.7
Release: 6
License: BSD
Group: System Environment/Base
URL: https://github.com/spahan/unixdmoain
BuildArch: noarch

Source: %{name}-%{version}.zip
BuildRoot: %{_topdir}/%{name}-%{version}.%{release}-root
Prefix: /opt/UD2

%description
UniDomain is a kerberos/ldap based system managment environment to
maintain the unix based systems on the campus unibas.ch.
It helps keeping user and group information up to date, enables 
a more fine grained, system and account managment.
Campus, departement or  global security and compliance settings can be 
applied in a fast and secure way.

%author: hanspeter@spahan.ch

%package client
Summary: Client side tools for UniDomain System
Group: System Environment/Base
Requires: krb5-workstation python-ldap cyrus-sasl-gssapi PyXML pam_krb5 

%description client
The client tools helps you to add your host
to the domain, manage the local user, group files and manage all
policy based settings and inform the administrator if really
bad things has happened.

%package admin
Summary: Administrative Tools fpr UniDomain System
Group: System Environment/Base
Requires: %{name}-client

%description admin
This package contains some tools to help with managing the UniDomain System itself.
It includes basic ldap and kerberos helper scripts.

%package www
Summary: UniDomain Web Interface
Group: System Environment/Base
Requires: %{name}-client httpd mod_ssl mod_auth_kerb mod_python

%description www
This package contains the Web Interface for the Uni Domain System.
It allows domads to edit host entries without require a ldap client
or knowledge about the internal UniDomain Database Layout.


%prep
%setup -n trunk/

%build
aclocal
autoreconf -i
./configure --enable-www --enable-admin
make

%install
prefix=${RPM_BUILD_ROOT}/opt/UD2
make install prefix=${prefix}

%post client
# add link for UD python lib
for python_lib_dir in `/bin/ls -dr /usr/lib/python2.?`; do
    if [ ! -e ${python_lib_dir}/site-packages/UniDomain ]; then
        ln -s /opt/UD2/lib ${python_lib_dir}/site-packages/UniDomain
    fi
done
# we backup some data just in case.
backup_dir=/var/cache/ud2/backup
if [ ! -d ${backup_dir} ]; then
    mkdir -p ${backup_dir}
fi
cp -f /etc/passwd ${backup_dir}/passwd.update
cp -f /etc/group ${backup_dir}/group.update
if [ $1 -eq 1 ]; then
    # backup pre ud2 data
    cp /etc/passwd ${backup_dir}/passwd.original
    cp /etc/group ${backup_dir}/group.original
    if  [ -e /etc/krb5.conf ]; then
        cp -H /etc/krb5.conf ${backup_dir}/krb5.conf.original 1>/dev/null 2>&1
    fi
    if [ -e /etc/openldap/ldap.conf  ]; then
        cp /etc/openldap/ldap.conf ${backup_dir}/ldap.conf.original 1>/dev/null 2>&1
    fi
    # add all required config files
    cp /opt/UD2/etc/ud2.conf /etc/ud2.conf
    cp /opt/UD2/etc/krb5.conf /etc/krb5.conf
    cp /opt/UD2/etc/ldap.conf /etc/openldap/ldap.conf
else
    # clean up some old messy things. do not clutter the global namespace!
    if [ -f /etc/krb5.conf.original ]; then
        /bin/mv /etc/krb5.conf.original ${backup_dir}/
    fi
    if [ -f /etc/openldap/ldap.conf.orignal ]; then
        /bin/mv /etc/openldap/ldap.conf.original ${backup_dir}/
    fi
fi
# make sure config files are world readable.
chmod 644 /etc/krb5.conf
chmod 644 /etc/openldap/ldap.conf


%preun client
if [ $1 -eq 0 ]; then
    # remove link to library from all python dists
    for python_lib_dir in `/bin/ls -dr /usr/lib/python2.?`; do
        if [ -h ${python_lib_dir}/UniDomain ]; then
            /bin/rm ${python_lib_dir}/UniDomain
        fi
        if [ -h ${python_lib_dir}/site-packages/UniDomain ]; then
            /bin/rm ${python_lib_dir}/site-packages/UniDomain
        fi
    done
fi

%postun client
echo "leaving backup in /var/cache/ud2"

%files client
%defattr(0644, root, root, 0755)
#need add dirs so rpm kills them on uninstall. Else we have a empty skeleton left.
%dir /opt/UD2
%dir /opt/UD2/etc
%dir /opt/UD2/lib
%dir /opt/UD2/lib/plugins
%dir /opt/UD2/lib/udPolicy
%dir /opt/UD2/sbin
%dir /opt/UD2/share
%doc /opt/UD2/share/LICENSE.TXT
%attr(0644, root, root) /opt/UD2/etc/ud2.conf
%attr(0644, root, root) /opt/UD2/etc/krb5.conf
%attr(0644, root, root) /opt/UD2/etc/ldap.conf
%attr(0755, root, root) /opt/UD2/bin
# sbin only for root
%attr(0750, root, root) /opt/UD2/sbin/add_host.py*
%attr(0750, root, root) /opt/UD2/sbin/hostedit.py*
%attr(0750, root, root) /opt/UD2/sbin/hostreg.py*
%attr(0750, root, root) /opt/UD2/sbin/hostrun.py*
%attr(0750, root, root) /opt/UD2/sbin/nfs_setup.py*
%attr(0750, root, root) /opt/UD2/sbin/register.sh
%attr(0750, root, root) /opt/UD2/sbin/list_hosts.py*
# use default attributes for lib
/opt/UD2/lib/__init__.py*
/opt/UD2/lib/afslib
/opt/UD2/lib/Classes.py*
/opt/UD2/lib/functions.py*
/opt/UD2/lib/udPolicyEngine.py*
/opt/UD2/lib/plugins/__init__.py*
/opt/UD2/lib/plugins/krb5_keytab.py*
/opt/UD2/lib/plugins/krb5_login.py*
/opt/UD2/lib/plugins/krb5.py*
/opt/UD2/lib/plugins/ldapdb.py*
#This should go to the admin package. But thats not finished yet.
/opt/UD2/lib/plugins/ldapdbadmin.py*
/opt/UD2/lib/udPolicy/*.py*

%files admin
%defattr(0750, root, root, 0750)
%doc /opt/UD2/share/doc
/opt/UD2/admin
/opt/UD2/lib/dbmcache.py*

%files www
# root can rw, httpd can r
%defattr(0644, root, apache, 0750) 
%attr(0644, root, root) /opt/UD2/etc/ud2_apache.conf
%attr(0644, root, root)/opt/UD2/etc/www_conf.xml
%attr(0755, root, root) /opt/UD2/sbin/cfsync.py*
/opt/UD2/lib/plugins/krb5_apache.py*
/opt/UD2/wwwlib


%changelog
* Mon Dec 16 2013 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.7-6
- improved registration procedure
* Wed Oct 16 2013 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.7-5
- various bugfixes
* Fri May 24 2013 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.7-3
- compatibility update
* Thu Sep 11 2011 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.6-2
- keep local group data for managed users
* Thu Jun 1 2011 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.6-0
- use autotools build system.
* Thu Dec 7 2010 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.5-6
- fixed dns update
* Thu Dec 7 2010 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.5-5
- removed transition code (2.4 to 2.5)
* Mon Dec 6 2010 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.5-3
- fixed deleting of core files after update.
* Thu Nov 25 2010 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.5-2
- adjusted file permissions
* Thu Nov 25 2010 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.5-1
- final release
* Mon Nov 08 2010 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.5rc3
- backported fixes from trunk into 2.5 branch
* Thu Nov 04 2010 Hanspeter Spalinger <h.spalinger@stud.unibas.ch> - 2.5
- Started using one SPEC file for all packages.
