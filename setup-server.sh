#!/bin/bash

set -eo pipefail

cd `dirname $0`

#CLIENT_IP=11.0.30.1
#`cat conf/client-ip.txt`
VIRTUAL_IP=`cat conf/virtual-ip.txt`
MY_CARD_IP=`./get-my-card-ip.sh`
#MY_TUNL_IP=`./get-my-tunl-ip`

if [ -z "$*" ]; then
	if ip link | grep -q ipip:; then
		echo "* skipping ipip ifs - seems created already"
	else
#		echo "* creating tunnel to client"
#		sudo ip tunnel add ipipt0 mode ipip remote $CLIENT_IP local $MY_CARD_IP ttl 255
#		sudo ip link set ipipt0 up
#		sudo ip link set ipipt0 mtu 1480
#		sudo ip addr add $MY_TUNL_IP/16 dev ipipt0

		echo "* creating ipip ifs"
		./create-ipip-ifs.sh
		sudo ip link set tunl0 up
		sudo ip link set ip6tnl0 up
		sudo ip addr add $MY_CARD_IP/32 dev ipip0
	fi

	echo "* disabling rp_filter feature on all ifs"
	for sc in $(sysctl -a 2>/dev/null | awk '/\.rp_filter/ {print $1}'); do
		sudo sysctl ${sc}=0 >/dev/null
	done

	if ip addr show | grep -q $VIRTUAL_IP; then
		echo "* skipping virtual ip $VIRTUAL_IP - seems configured already"
	else
		echo "* configuring virtual ip $VIRTUAL_IP"
		sudo ip addr add $VIRTUAL_IP/32 dev lo
	fi
else
	echo "* unconfiguring virtual ip $VIRTUAL_IP"
	sudo ip addr del $VIRTUAL_IP/32 dev lo

	echo "* removing ipip ifs"
	sudo ip addr del $MY_CARD_IP/32 dev ipip0
	./remove-ipip-ifs

#	echo "* removing tunnel to client"
#	sudo ip tunnel del ipipt0
	sudo rmmod ipip
	sudo rmmod ip_tunnel
	sudo rmmod ip6_tunnel
fi

echo `basename $0` "finished successfully."
exit 0
