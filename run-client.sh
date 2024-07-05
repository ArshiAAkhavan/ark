#!/bin/bash 

cargo build --release
sudo setcap cap_net_admin=eip ./target/release/ark

./target/release/ark "$@" &
pid=$!

# Initialize variables
remote_value=""

# Iterate through the arguments to find the --remote flag
while [[ $# -gt 0 ]]; do
  case $1 in
    --remote)
      remote_value="$2"
      shift # past argument
      shift # past value
      ;;
    *)
      shift # past argument or value
      ;;
  esac
done

# Print the value of the remote flag
echo "Remote flag value: $remote_value"
if [[ $remote_value == *":"* ]]; then
  remote_host="${remote_value%%:*}"
else
  remote_host="$remote_value"
fi

# Print the first part of the remote flag value
echo "Remote host: $remote_host"



trap 'kill $pid' INT TERM

sleep 5

# replace with server IP

while IFS= read -r line; do
    eval "sudo ip route add $line"
done <<< $(ip route | grep default | sed "s/default/$remote_host/g")
sudo ip route add default dev ark-0
echo "route neverssl.com"

wait $pid
