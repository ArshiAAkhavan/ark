#/bin/bash 

cargo build --release
sudo setcap cap_net_admin=eip ./target/release/ark

./target/release/ark &
pid=$!
sudo ip addr add 172.30.0.12/24 dev ark
sudo ip link set up dev ark

trap "kill $pid" INT TERM
wait $pid
