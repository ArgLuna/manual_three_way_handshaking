# manual_three_way_handshaking
A simple implementation of three way handshaking manually.
Test OS: Ubuntu 16.04
Still WIP.

2018.11.05
Initial commit

Can send SYN and ACK, but cannot complete the handshaking.
The reason is that we send the SYN manully, which didn't leave any record on the network stack, so the OS didn't know there was a SYN sended.
When a SYN/ACK comes in, the OS can't find any corespond SYN so that it takes the SYN as an illegal connection.
