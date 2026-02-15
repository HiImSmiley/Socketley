#!/bin/bash
# UDP Echo Server Example
# Demonstrates fire-and-forget messaging with UDP.
# Each datagram = one message (no line-parsing).

set -e

echo "Starting daemon..."
socketley daemon &
sleep 0.5

echo "Creating UDP server on port 9000..."
socketley create server udpecho -p 9000 --udp -b -s

echo "Sending datagrams..."
echo "hello" | socat - UDP:localhost:9000
echo "world" | socat - UDP:localhost:9000

sleep 0.5

echo ""
echo "Status:"
socketley ls

echo ""
echo "Cleanup..."
socketley stop udpecho
socketley remove udpecho
