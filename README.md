# Ark
Ark: a VPN protocol based on layer 4 protocol swapping and more!

# setup
## Server
to run the server use the following command:
```bash
./run-server.sh --local 0.0.0.0:9091 -m server -s 172.16.0.1/24
```
where `local` is the local address for udp socket to bind and the `-s` subnet range specifies the ip range in which the client and the server work on.

## Client
```bash
./run-client.sh --local 0.0.0.0:7070 -r 87.247.189.1:9091 -m client
```
where `local` is the local address for udp socket to bind and `-r` specifies the remote address in which the server resides.

enjoy!
