#!/bin/bash 

cargo build --release
sudo setcap cap_net_admin=eip ./target/release/ark

./target/release/ark "$@" &
pid=$!

trap "kill $pid" INT TERM
wait $pid
