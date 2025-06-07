#!/bin/bash

echo "--- Cleaning up previous setup (if any) ---"
sudo ip netns del sender-ns 2>/dev/null
sudo ip netns del receiver-ns 2>/dev/null
sudo ip link del veth-main-brg 2>/dev/null # Xóa cầu nối cũng sẽ xóa peer của nó

echo "--- Setting up namespaces ---"
sudo ip netns add sender-ns
sudo ip netns add receiver-ns

echo "--- Setting up data link (sender <-> receiver) ---"
sudo ip link add veth-s type veth peer name veth-r
sudo ip link set veth-s netns sender-ns
sudo ip link set veth-r netns receiver-ns
sudo ip netns exec sender-ns ip link set veth-s up
sudo ip netns exec receiver-ns ip link set veth-r up

echo "--- Setting up management/bridge link (receiver <-> main) ---"
sudo ip link add veth-agent-brg type veth peer name veth-main-brg
sudo ip link set veth-agent-brg netns receiver-ns
sudo ip addr add 192.168.200.1/24 dev veth-main-brg
sudo ip link set veth-main-brg up
sudo ip netns exec receiver-ns ip addr add 192.168.200.2/24 dev veth-agent-brg
sudo ip netns exec receiver-ns ip link set veth-agent-brg up

echo "--- Environment is ready ---"
echo "To run agent: sudo ip netns exec receiver-ns ./PacketCaptureAgent"
echo " (Ensure config points to veth-r and server IP 192.168.200.1)"
echo "To run tcpreplay: sudo ip netns exec sender-ns tcpreplay -i veth-s ..."
echo "To run server: ./PacketCaptureServer (in main namespace)"
