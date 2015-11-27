#!/bin/sh


/opt/UD2/bin/renew.py 
/opt/UD2/admin/AFS_sync_unibasUser.py 1> /var/log/AFS_sync_unibasUser.log 2>&1 &

while true;
do 
    /opt/UD2/bin/renew.py
    sleep 72000
done &

tail -f /var/log/AFS_sync_unibasUser.log


