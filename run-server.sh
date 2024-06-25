#!/bin/bash 

cargo build --release
sudo setcap cap_net_admin=eip ./target/release/ark

./target/release/ark "$@" &
pid=$!


trap "kill $pid" INT TERM

sleep 1
iptables -t nat -A POSTROUTING -s 172.16.0.0/24 ! -d 172.16.0.0/24 -j MASQUERADE
echo "nat is done"

wait $pid

