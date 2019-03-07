#!/bin/bash

set -eo pipefail

cd `dirname $0`

#KATRAN_SERVER=./build/example/katran_server_grpc
KATRAN_SERVER=./build/example/simple_katran_server

if [ ! -f $KATRAN_SERVER ]; then
	echo "katran server executable file not found"
	exit 1
fi
if [ ! -x $KATRAN_SERVER ]; then
	echo "katran server file $KATRAN_SERVER is not executable"
	exit 1
fi

KATRAN_IF=`cat conf/katran-if.txt`
DEFAULT_ROUTE_MAC=`./get-default-route-mac.sh`
PID_FILE=katran-server.pid
BALANCER_PROG="deps/bpfprog/bpf/balancer_kern.o"
HEALTHCHECKER_PROG="deps/bpfprog/bpf/healthchecking_ipip.o"
#FORWARDING_CPU_CORES="8,9,10,11,12,13,14,15,24,25,26,27,28,29,30,31"
FORWARDING_CPU_CORES="0,1,2,3"

#if [ -s $PID_FILE ]; then
#	echo "Seems katran server is running already. Remove/nulify $PID_FILE if not."
#	exit 1
#fi
echo $$ >$PID_FILE

if ! tc qd show dev $KATRAN_IF | grep -q clsact; then
	echo "* adding qdisc dev $KATRAN_IF clsact"
	sudo tc qdisc add dev $KATRAN_IF clsact
fi

./remove-ipip-ifs.sh > /dev/null 2>&1
echo "* creating ipip ifs"
./create-ipip-ifs.sh

echo "* starting katran server"
CMD="${KATRAN_SERVER} \
	-balancer_prog ${BALANCER_PROG} \
	-default_mac=${DEFAULT_ROUTE_MAC} \
	-healthchecker_prog ${HEALTHCHECKER_PROG} \
	-forwarding_cores=${FORWARDING_CPU_CORES} \
	-intf=${KATRAN_IF} -ipip_intf=ipip0 -ipip6_intf=ipip60 \
	-shutdown_delay 1000 -lru_size=100000 -priority 2307 -prog_pos 8"
CMD=$(echo "$CMD" | tr -d '\t')
if [ -f /sys/fs/bpf/jmp_${KATRAN_IF} ]; then
	CMD="$CMD -map_path /sys/fs/bpf/jmp_${KATRAN_IF} -prog_pos=2"
fi
echo "+ $CMD"
sudo $CMD

echo "* removing ipip ifs"
./remove-ipip-ifs.sh

echo "* deleting qdisc dev $KATRAN_IF clsact"
sudo tc qdisc del dev $KATRAN_IF clsact

printf "" > $PID_FILE

exit 0
