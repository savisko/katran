#!/bin/bash

set -eo pipefail

if [ ! -f conf/server-ips.txt ]; then
	echo "Configuration file with servers IPs not found - conf/server-ips.txt"
	exit 1
fi
if [ ! -f conf/virtual-ip.txt ]; then
	echo "Configuration file with VIP not found - conf/virtual-ip.txt"
	exit 1
fi

VIRTUAL_IP=`cat conf/virtual-ip.txt`
PORT=${1-22}
TARG=${2--t}

sudo ./katran-client -A $TARG $VIRTUAL_IP:$PORT
for real_ip in `cat conf/server-ips.txt`; do
	sudo ./katran-client -a $TARG $VIRTUAL_IP:$PORT -r $real_ip
done

exit 0
