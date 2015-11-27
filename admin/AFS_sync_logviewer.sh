#!/bin/sh

sed -e '/^$/d' -e '/already exists/d' /var/log/AFS_sync_unibasUser.log | less
