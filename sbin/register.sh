#!/usr/bin/env bash
#
# new hosts must be registered with this script
# 

/opt/UD2/sbin/hostreg.py $1 || exit $?
echo "---------------------------------------------"
echo " Updating root password"
case `uname -s` in
    FreeBSD)
        pwgen 12 1 | tee /root/.passwd | pw mod user root -h 0;;
    Linux)
        pwgen 12 1 | tee /root/.passwd | passwd --stdin root;;
    *)
        echo "Unknown System "`uname -s`" You need change the root Password yourself";;
esac
chmod 400 /root/.passwd
echo -n "root password is "
cat /root/.passwd
echo "It has been saved to /root/.passwd for convinience."
echo "Hi,\n This is your installer@`hostname -f`\n Your new root password has been changed to " | cat - /root/.passwd | gpg -e -a -r root-urz@unibas.ch --trust-model always | mail -s "Registered `hostname -f`" root-urz@unibas.ch
echo "---------------------------------------------"
echo "Wating for Kerberos and ldap Sync. Please wait"
kinit -k host/`hostname -f` 2>&1 1>/dev/null
while [ $? -ne 0 ]; do
    sleep 10
    kinit -k host/`hostname -f` 2>&1 1>/dev/null
done
/opt/UD2/sbin/hostrun.py 
echo "---------------------------------------------"
echo "Running cf-agent to set up UD managed policies. (logging into /root/register.cflog)"
/var/cfengine/bin/cf-agent -KI > /root/register.cflog 
