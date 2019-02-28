#!/bin/bash

sudo ip link set down dev ipip0
sudo ip link set down dev ipip60
sudo ip link del ipip0 type ipip external
sudo ip link del ipip60 type ip6tnl external
sudo rmmod ipip
sudo rmmod ip_tunnel
sudo rmmod ip6_tunnel

exit 0
