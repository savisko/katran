#!/bin/bash

set -eo pipefail

sudo ip link add ipip0 type ipip external
sudo ip link add ipip60 type ip6tnl external
sudo ip link set up dev ipip0
sudo ip link set up dev ipip60
sudo ip addr add 127.0.0.42/32 dev ipip0

exit 0
