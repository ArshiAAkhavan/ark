#!/bin/bash 

cargo build --release
sudo setcap cap_net_admin=eip ./target/release/ark

./target/release/ark "$@" &
pid=$!


trap 'kill $pid' INT TERM

sleep 1

sudo ip route add 87.247.189.1 via 10.30.100.1  dev wlp0s20f3
sudo ip route add default dev ark-0

echo "route neverssl.com"

wait $pid
