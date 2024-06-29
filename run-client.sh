#!/bin/bash 

cargo build --release
sudo setcap cap_net_admin=eip ./target/release/ark

./target/release/ark "$@" &
pid=$!


trap 'kill $pid' INT TERM

sleep 1

# replace with server IP
sudo ip route `ip route | grep default | sed 's/default/87.247.189.1/g'`
sudo ip route add default dev ark-0

echo "route neverssl.com"

wait $pid
