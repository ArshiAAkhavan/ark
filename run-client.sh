#!/bin/bash 

cargo build --release
sudo setcap cap_net_admin=eip ./target/release/ark

./target/release/ark "$@" &
pid=$!


trap "kill $pid" INT TERM

sleep 5
sudo ip route add 34.223.124.45 dev ark-0
echo "route neverssl.com"

wait $pid
