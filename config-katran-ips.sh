#!/bin/bash

set -eo pipefail

if [ ! -f conf/server-ips.txt ]; then
	echo "Configuration file with servers IPs not found - conf/server-ips.txt"
	exit 1
fi

./add-vip-port.sh 22
./add-vip-port.sh 5001
./add-vip-port.sh 5001 -u

fwmark=1000
for real_ip in `cat conf/server-ips.txt`; do
	./katran-client -new_hc $real_ip -somark $fwmark
	fwmark=$((fwmark + 1))
done

exit 0
