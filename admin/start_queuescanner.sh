#!/bin/sh


LOGFILE="/var/log/idscanner.log"

cd /opt/UD2/admin
python -O idscanner.pyo  1> ${LOGFILE} 2>&1 &
cd -


# python -O idscanner.pyo  


