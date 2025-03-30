# CS 4440 Twig project tools

## Tools list:

- [shim.py](README.md#shimpy)
- [socket_time.c](README.md#socket_timec)
- [make_pcap.sh](README.md#make_pcapsh)
- [twig_test.sh](README.md#twig_testsh)

## Overview

***UPDATE Mar 29 ~10:30pm - it appears the latest version of scapy available through `apt` is `2.5.0` which had an incompatibility with a function the shim was using to write packets. Please pull again if you pulled prior to this commit.***

**Update Mar 29 11:52pm - the performance loss was actually due to the high traffic my onther machine was experiencing,  a more robust filter has been added to the interface sniffer, and it has been transferred to a callback mechanic to improve performance. Still compatible with both scapy 2.5.0 and 2.6.1. Please pull this version.**

To run a simple test using these tools, here are the steps:

1. Open 3 terminals in this repository's directory
2. In one terminal, run `./twig_test.sh`
	- Authenticate when requested to start the shim
	- You'll know it is running as expected when you see the line `press ctrl+d to stop `
3. In another terminal, start your `twig` on the network using `./twig -i 172.31.128.2_24` (replace the interface specification if you change the network used in `twig_test.sh`)
4. In the final terminal, you can test using `ping` or `socket_time` (or similar programs that your `twig` can respond to)
The format is `ping 172.31.128.2` or `socket_time 172.31.128.2` (replace the ip address if you change the ip address your `twig` is listening on)


**NOTE: if you are unable to run the scripts, you may need to make them executable using the following commands:**
```
chmod +x twig_test.sh
chmod +x make_pcap.sh
```

Also note that the capture file is not removed when the shim is stopped, this is to make it easier to review if your packets are correct or not, though `make_pcap.sh` or `twig_test.sh` *will **overwrite** existing files* if started with the same network configured. 

## shim.py

### Description
The shim sits between the pcap file we use as an interface for twig and the real network. 

The shim uses a direct forwarding mechanism, so we can only talk to things on the same local machine as the shim/twig. It also only forwards ipv4 packets which are

- In the pcap file, from the network that file represents,and destined to something not on that network

or

- On the real interface specified and destined to the network the pcap file represents.


### Requirements

To run the shim you will need the following:

- Python `3.X` (tested with `3.12.2`)
- Python module `scapy`
- (Usually) Default modules `threading`, `socket`, `ipaddress`, `sys`, `signal`, `json`, `netifaces`, `argparse`

Installing `scapy` (and any other reported missing modules) will require either:

1. Using a virtual environment for python such as via `venv` 
2. Installing scapy with root via `sudo pip install scapy` or `sudo apt install python3-scapy`

**NOTE: running the shim requires root access since it is accessing your network interface to sniff for packets and is injecting packets 'sent' from the pcap file.**

## socket_time.c
socket_time.c is a minimal client for the Time Protocol (udp port 37) specified by [RFC 868](https://www.rfc-editor.org/rfc/rfc868.html)

Compile manually or using the built in `make` rules by running 
```
make socket_time
```

then you can request time from any machine running the time server on port 37.

(you can test it on `132.235.1.1`)

Output is in the format 

```
The time on 132.235.1.1 is 0x214b8feb
```

Note that the timestamp `0x214b8feb` is in big endian, hex, and is seconds since `00:00 1 January 1900 GMT` as specified in the RFC. 

Converted to  a human readable format, it is 

```
Thursday, March 27, 2025 3:57:21 AM GMT
```


## make_pcap.sh

This script serves to make an empty pcap file with some default header parameters.

run using the format 

```
./make_pcap.sh <pcapfilename>
```

e.g.

```
./make_pcap.sh 172.31.128.0_24.dmp
```

or just use twig_test.sh to start the shim and make the pcap file at the same time.

## twig_test.sh

### Description

This script creates a pcap file with network `172.31.128.0/24`, tries to determine and use your default interface, and starts a copy of [shim.py](README.md#shimpy) between that pcap file and the determined interface.

To close down the shim this script starts, simply use `ctrl+d` or `ctrl+c` in the terminal it is running in.

If your default interface contains spaces, edit the script to have the name already specified or enable it to take the interface as an argument. Comments in the script identify where to do this.

To use a new network address from the default, edit the script to use your chosen network (non-public IPs only) or enable it to take the network as an argument. Comments in the script identify where to do this.

**NOTE: This script will prompt for password since you need root to run the shim.**

### Requirements

This script has all the requirements to run shim, and additionally uses lots of BASH specific expansions such as the arithmetic expansion notation `$(( <expr> ))`.
