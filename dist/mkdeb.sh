DEB_BUILD_ROOT=/tmp/unidomain-client_2.7-2
DEB_SOURCE_ROOT=`pwd`

until [ -z "$1" ]; do
    case $1 in
        '-s'|'--source') DEB_SOURCE_ROOT=$2; shift 2;;
        *)
            print "usage: $0 [options] revision\n\n\t revision is the revision to build.\n\n\
\toptions\n
\t\t -s, --source <path>\t where the source is located. (defaults to current working directory)\n"
            return 2;;
    esac
done

#create directories
echo creating dirs
mkdir -p $DEB_BUILD_ROOT
mkdir -p $DEB_BUILD_ROOT/DEBIAN
mkdir -p $DEB_BUILD_ROOT/etc/cron.d
mkdir -p $DEB_BUILD_ROOT/opt/UD2
mkdir -p $DEB_BUILD_ROOT/opt/UD2/bin
mkdir -p $DEB_BUILD_ROOT/opt/UD2/sbin
mkdir -p $DEB_BUILD_ROOT/opt/UD2/lib
mkdir -p $DEB_BUILD_ROOT/opt/UD2/lib/plugins
mkdir -p $DEB_BUILD_ROOT/opt/UD2/lib/udPolicy
mkdir -p $DEB_BUILD_ROOT/opt/UD2/etc
mkdir -p $DEB_BUILD_ROOT/var/cache/ud2
#set correct ownership
#chmod -R 755 $DEB_BUILD_ROOT/opt/UD2
chmod -R 755 $DEB_BUILD_ROOT

echo copy lib
#copy relevatn parts of lib
for file in lib/*.py; do
    echo "$DEB_SOURCE_ROOT/$file -> $DEB_BUILD_ROOT/opt/UD2/$file"
    cp $DEB_SOURCE_ROOT/$file $DEB_BUILD_ROOT/opt/UD2/$file
    chmod 644 $DEB_BUILD_ROOT/opt/UD2/$file
done
for file in lib/plugins/*.py; do
    echo "$DEB_SOURCE_ROOT/$file -> $DEB_BUILD_ROOT/opt/UD2/$file"
    cp $DEB_SOURCE_ROOT/$file $DEB_BUILD_ROOT/opt/UD2/$file
    chmod 644 $DEB_BUILD_ROOT/opt/UD2/$file
done
for file in lib/udPolicy/*.py; do
    echo "$DEB_SOURCE_ROOT/$file -> $DEB_BUILD_ROOT/opt/UD2/$file"
    cp $DEB_SOURCE_ROOT/$file $DEB_BUILD_ROOT/opt/UD2/$file
    chmod 644 $DEB_BUILD_ROOT/opt/UD2/$file
done

echo copy tools
#copy bin/sbin tools
for file in bin/hostinfo bin/*.py; do
    echo "$DEB_SOURCE_ROOT/$file -> $DEB_BUILD_ROOT/opt/UD2/$file"
    cp $DEB_SOURCE_ROOT/$file $DEB_BUILD_ROOT/opt/UD2/$file
    chmod 755 $DEB_BUILD_ROOT/opt/UD2/$file
done
for file in sbin/*.py sbin/*.sh; do
    echo "$DEB_SOURCE_ROOT/$file -> $DEB_BUILD_ROOT/opt/UD2/$file"
    cp $DEB_SOURCE_ROOT/$file $DEB_BUILD_ROOT/opt/UD2/$file
    chmod 755 $DEB_BUILD_ROOT/opt/UD2/$file
done

echo copy config files
#copy config files
cp $DEB_SOURCE_ROOT/etc/ud2.conf $DEB_BUILD_ROOT/etc/ud2.conf
chmod 755 $DEB_BUILD_ROOT/etc/ud2.conf
cp $DEB_SOURCE_ROOT/etc/krb5.conf $DEB_BUILD_ROOT/opt/UD2/etc/krb5.conf
cp $DEB_SOURCE_ROOT/etc/ldap.conf $DEB_BUILD_ROOT/opt/UD2/etc/ldap.conf

cat > $DEB_BUILD_ROOT/opt/UD2/etc/pam.README << 'EOF'
see http://www.debian-administration.org/articles/570
for how to configure pam
EOF
#copy DEBAIN controll dir
cp -r $DEB_SOURCE_ROOT/dist/DEBIAN $DEB_BUILD_ROOT/
chmod 755 $DEB_BUILD_ROOT/DEBIAN/postrm
chmod 755 $DEB_BUILD_ROOT/DEBIAN/prerm
chmod 755 $DEB_BUILD_ROOT/DEBIAN/postinst
chmod 644 $DEB_BUILD_ROOT/DEBIAN/conffiles
rm -rf $DEB_BUILD_ROOT/DEBIAN/.svn
#chmod 755 $DEB_BUILD_ROOT/DEBIAN/preinst

# this is debian/ubuntu. we can rely on python be python2 binary
for x in `find ${DEB_BUILD_ROOT} -name '*.py' -print`; do grep 'bin/env' $x; done

for x in `find ${DEB_BUILD_ROOT} -name '*.py' -print`; do sed -i '/^#!.*python2/c\#!/usr/bin/python' $x; done
#finaly make the deb package.
dpkg-deb --build $DEB_BUILD_ROOT
