#!/bin/sh


/opt/UD2/admin/AFS_sync_unibasUser.py 1> /var/log/AFS_sync_unibasUser.log 2>&1
/usr/sbin/vos rel unibasHome -v 1>> /var/log/AFS_sync_unibasUser.log 2>&1



