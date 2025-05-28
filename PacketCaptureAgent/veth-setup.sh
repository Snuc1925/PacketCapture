#!/bin/bash
ip link add veth0 type veth peer name veth1
ip addr add 192.168.100.1/24 dev veth0
ip addr add 192.168.100.2/24 dev veth1
ip link set veth0 up
ip link set veth1 up