# CS 4440 Twig project tools

## Outline 

### Main Sections:
- [Issues and Clarifications](README.md#issues-and-clarifications-ongoing-updates)
- [Running Overview](README.md#running-overview)
- [Running with Docker](README.md#running-with-docker)
- [Testing](README.md#testing)

### Tools:

- [shim.py](README.md#shimpy)
- [socket_time.c](README.md#socket_timec)
- [udpping](README.md#udpping)
- [make_pcap.sh](README.md#make_pcapsh)
- [twig_test.sh](README.md#twig_testsh)

- [docker_test.sh](README.md#docker_testsh)
- [dockershim.sh](README.md#dockershimsh)
- [cleandocker.sh](README.md#cleandockersh)

- [CHAIN.sh](README.md#chainsh)

## Issues and Clarifications (ongoing updates)

- **(Issue)** `Ctrl+d` or `Ctrl+c` will not stop the shim if it is no longer recieving packets to forward to the pcap file (it only checks if it should stop when it gets another packet) 
	- To stop it then, you can do one of the following
		- Press `Ctrl+d` or `Ctrl+c` as usual, then send and additional packet to the shim using `ping 172.31.128.2` (or using another of the utilities given) 
		- Press `Ctrl+\` to forcibly kill the shim. The shim is multi-threaded, not multi-process, so this will correctly terminate it.
- **(Issue)** The first packet recieved by the shim is often discarded. So assume that the first packet will be lost.
	- I recommend either testing first with `ping` or run `time_socket` first, expecting it to go unanswered.
- **(Clarification)** The shim will display a warning when it writes the first packet:  
	- `WARNING: PcapWriter: unknown LL type for bytes. Using type 1 (Ethernet)`
- **(Clarification)** For debugging there are a few useful tools present.
	- For debugging checksums, Wireshark can check them for you and let you know if they are right or not. To enable this for UDP and IPv4, open wireshark and navigate to:
		- `Edit -> Preferences -> Protocols -> IPv4` and check
			- [x] ` Validate the IPv4 checksum if possible`
		- `Edit -> Preferences -> Protocols -> UDP` and check
			- [x] ` Validate the UDP checksum if possible`
	- For viewing packets as they arrive in the .dmp file we use as a network, the `twig_test.sh` script has the ability to start a live wireshark capture session when it starts the shim. To activate this, run the script with the `-w` option like so:
		```
		./twig_test.sh -w
		```
		Note that this wireshark window will need to be closed manually, as it does not close when the shim is killed.
		
		Also note that when running with docker, this wont work, you'll instead need to start a tailing wireshark capture yourself using a command like so:
		```
			tail -f -c +0 172.31.128.0_24.dmp | wireshark -k -i -
		```
		
	- For debugging if the shim is seeing your packets or is missing them, you can add `-d` or `-dd` to the line which runs the shim in `twig_test.sh` i.e. change
		```
		sudo python3 shim.py -n "${IFACE_ARG}" -i "${EXT_IFACE_NAME}"
		```
		to
		```
		sudo python3 shim.py -n "${IFACE_ARG}" -i "${EXT_IFACE_NAME}" -d
		```
		this will make it output a message and a packet summary every time it processes a packet from the pcap file.
- **TODO:** Add support for multi-network setup behind the shim.


## Requirements

Requirements are listed in **bold**, suggested optional software is *italicized*.

### Without Docker

- **Two machines**
	- Root access on both
	- Ability to establish one as the `next-hop` for select traffic from the other (typically means both are on the same LAN)
- **ping**
- **gcc**
- **make**
- **ip**
- **Python 3.7+**
	- **scapy 2.5.0+**
	- **netifaces**
- **bash**
- **sudo**
- **bc**
- **xxd**
- **ifconfig**
- **libpcap**
- *wireshark*

### With Docker

- **One machine**
	- root access
- **docker**
- **ping**
- **gcc**
- **make**
- **ip**
- *wireshark*

## Running Overview

TO run in the scenario without docker, we will be using one machine to run `twig` and `shim.py`, and the other to send traffic using `ping`, `udpping`, or `socket_time`. 

From now on, I will refer to the machine running the `twig` and `shim.py` as the *twig machine*, and the machine running `ping`, `udpping`, or `socket_time` as the *ping machine*. Any commands will be prefixed with `twig:` or `ping:` to represent which machine they are to be run on.

### Setup

We will start by establishing routes from the *ping machine* to the twigs on the *twig machine*. First we need the IP address of the *twig machine*, which can be obtained using the `ip` command on the *twig machine*. 

I.e. 
```c
twig: ip r | grep default
default via 192.168.1.1 dev wlp170s0 proto dhcp src 192.168.1.42 metric 600 
```
> Here, we see the address for our default interface is `192.168.1.42`

Then on the *ping machine* we establish routes that will direct traffic intended for the twigs to our `twig machine`.

I.e.
```c
ping: sudo ip r add 172.31.128.0/24 via 192.168.1.42
```

Now we can start the shim and `twig` on the *twig machine* using 
```
twig: ./twig_test.sh
```
and in another terminal
```
twig: ./twig -i 172.31.128.2_24
```

---

**NOTE: the first few packets are likely to get lost, similar to the issue listed in [Issues](README.md#issues-and-clarifications-ongoing-updates).**

To make sure this doesnt affect our results, 

run 
```
ping: ./socket_time 172.31.128.2
^C
```
(the `^C` represents killing it with ctrl/command C)

This sends a first packet to the shim which most likely will be lost, but will ensure future packets will not be.

---

Finally we can send traffic from our *ping machine*:
```
ping: ping 172.31.128.2
```
```
ping: udpping 172.31.128.2
```
```
ping: socket_time 172.31.128.2
```

### Repeat Running

You can run `ping`, `udpping`, or `socket_time` on the *ping machine* repeatedly without adverse effects aside from the growing pcap file on the *twig machine*.

If you need to restart your twig, then also restart the shim, but no other action is needed.

### Shutdown

To fully shut down all components of this project and return everything to the original state, we need to do the following:

- Kill the shim script
- Kill twig
- On the *ping machine*, run
```
sudo ip r del 172.31.128.0/24
```


<!--

**Compatible with scapy Version 2.5.0+**

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


-->


## Running with Docker

This new version of the shim can only communicate with remote hosts, it cannot do loopback connections. So docker allows us to abstract this and do loopback connections in a way that appears as a remote connection to the shim.
Additionally, docker allows us to have a strict environment and allow better portability across systems.

### Setup

For initial setup, we will build the necessary components to run our shim in docker and have routes to get to it appropriately. 

To begin, open three terminals with this repository as the working directory.

Start by running the `docker_test.sh` script:

*__Note__: if you do __not__ want the ip route it adds and the docker network it creates to be removed when you stop the shim, __remove__ the `--rm` option.*
```c
./docker_test.sh --rm
```

Now, in a separate temrinal window, start twig:

```c
./twig -i 172.31.128.2_24
```

Finally we can send traffic from another terminal window:
```
ping 172.31.128.2
```
```
udpping 172.31.128.2
```
```
socket_time 172.31.128.2
```


### Shutdown commands

If you chose not to provide the `--rm` option to the `docker_test.sh` script, you will need to run the following commands to remove the docker network and the ip route it adds.

```c
docker network remove twignet
sudo ip route del 172.31.128.0/24
```


## Testing

***TESTING SECTION IS OUTDATED***

**This testing section was written for the loopback version, which is now outdated. The only changes made are in the setup procedure, please follow the procedure in the [Running Overview](README.md#running-overview) or the [Running with Docker](README.md#running-with-docker) sections**



This section will detail exactly how to run tests that check basic functionality for your twig program.

The basic format for each test will be very similar to the procedure detailed in the [Overview](README.md#overview), but will be careful to avoid known issues and will have a higher level of detail.

Formatting:
- Clarifying comments will be italicized like *this*
- Specific important elements will be bold like **this**
- Placeholder elements of commands will be indicated using angle brackets (`<>`) with a description of the value they represent contained.
- Commands, program names, file names, and single-line output will be isolated in in-line code segments like `this`
- Multiline output and results will be isolated in multiline code blocks like
```
this
```

Notes:
- IP addresses will be specified absolute assuming a default `twig_test.sh`. If you modify `twig_test.sh` all IP addresses will need to be updated to follow. Additionally, IP addresses specified for use with `twig`, `ping`, `socket_time`, and `udpping` are assumed to be used exactly as written. modifying the IP in any stepp will require modifying it in all related steps.
- Each test has the same shutdown process, and the same startup process for the shim and twig.
	- To run **all tests** quickly, you can simply perform **steps 1-5** from any of the following test sections, then perform **steps 6+** from each test in any order sequentially **without performing shutdown in-between.**

### Test 1 (ICMP Ping)

#### Procedure
1. Open 3 terminal windows, each with this repository as their working directory.
2. Create a symbolic link to your twig program in the local directory by running the following command in **terminal 1**: `ln -s <your twig directory>/twig ./twig `
	- *Make sure to replace `<your twig directory>` with the directory your twig program is present in, and ensure you have a binary named `twig` in that directory.*
3. In **terminal 1**, run `./twig_test.sh`
	- Authenticate when prompted
	- *You'll know it is running as expected when you see the line `press ctrl+d to stop `*
4. In **terminal 2**, start your `twig` on the pcap file's network by running the command `./twig -i 172.31.128.2_24`
	- *this gives your twig an interface with IP `172.31.128.2` on the network `172.31.128.0/24`*
5. In **terminal 3**, run `./socket_time 172.31.128.2`, then press `Ctrl+c` to stop `socket_time`.
	- *This is to get around the issue of the first packet being ignored...* 
6. In **terminal 3**, run the command `ping -c 15 172.31.128.2` 

#### Shutdown

For shutting down, there is a known issue witht he shim, so follow these steps to shut down cleanly:
1. In **terminal 3**, run `ping 172.31.128.2`
	- *This will give packets to the shim and let it check for the shutdown signal. (See [Issues](README.md#issues-and-clarifications-ongoing-updates).)*
2. In **terminal 1**, press `Ctrl+d`
	- *`test_twig.sh` should stop running within a second, when `shim.py` recieves a packet.*
3. In **terminal 3**, press `Ctrl+c`
	- *`ping` should stop immediately.*
3. In **terminal 2**, press `Ctrl+c`
	- *`twig` should stop immediately*

#### Expected Results

The output of the `ping` client from **step 6** is what matters. 

Example **Good** output in **terminal 3** from **step 6**:
```
sspringer-fedora-Twig-tools: ping -c 15 172.31.128.2
PING 172.31.128.2 (172.31.128.2) 56(84) bytes of data.
64 bytes from 172.31.128.2: icmp_seq=1 ttl=20 time=15.8 ms
64 bytes from 172.31.128.2: icmp_seq=2 ttl=20 time=27.6 ms
64 bytes from 172.31.128.2: icmp_seq=3 ttl=20 time=17.9 ms
64 bytes from 172.31.128.2: icmp_seq=4 ttl=20 time=21.7 ms
64 bytes from 172.31.128.2: icmp_seq=5 ttl=20 time=14.6 ms
64 bytes from 172.31.128.2: icmp_seq=6 ttl=20 time=24.7 ms
64 bytes from 172.31.128.2: icmp_seq=7 ttl=20 time=21.5 ms
64 bytes from 172.31.128.2: icmp_seq=8 ttl=20 time=20.7 ms
64 bytes from 172.31.128.2: icmp_seq=9 ttl=20 time=15.7 ms
64 bytes from 172.31.128.2: icmp_seq=10 ttl=20 time=23.8 ms
64 bytes from 172.31.128.2: icmp_seq=11 ttl=20 time=13.7 ms
64 bytes from 172.31.128.2: icmp_seq=12 ttl=20 time=22.7 ms
64 bytes from 172.31.128.2: icmp_seq=13 ttl=20 time=23.9 ms
64 bytes from 172.31.128.2: icmp_seq=14 ttl=20 time=21.7 ms
64 bytes from 172.31.128.2: icmp_seq=15 ttl=20 time=19.5 ms

--- 172.31.128.2 ping statistics ---
15 packets transmitted, 15 received, 0% packet loss, time 14025ms
rtt min/avg/max/mdev = 13.718/20.374/27.581/3.946 ms
```

Key components to make sure are correct:
- 0% packet loss
- no `(DUP!)` warnings on any responses

##### Common issues and causes:

- If the first packet (response where `icmp_seq=1`) is missing, verify **Step 5** was performed. If Shutdown has not yet been performed, you may repeat **Step 6** and check the output of that new run.

- If other packets are missing, check first if the `172.31.128.0.dmp` file contains all requests but not all expected responses. 
	- If it does, the issue likely lies with your twig not replying to everything
	- If it does not, the issue is likely with t e shim - contact me (Silas) and we'll figure it out.

- If warnings with `(DUP!)` are present, the issue is likely either:
	- Two `twig`s are running simultaneously with the same interface IP and both are responding
	- The one running `twig` is not correctly keeping its place in the pcap file, so is reading the request multiple times.

### Test 2 (UDP Ping)

#### Procedure
1. Open 3 terminal windows, each with this repository as their working directory.
2. Create a symbolic link to your twig program in the local directory by running the following command in **terminal 1**: `ln -s <your twig directory>/twig ./twig `
	- *Make sure to replace `<your twig directory>` with the directory your twig program is present in, and ensure you have a binary named `twig` in that directory.*
3. In **terminal 1**, run `./twig_test.sh`
	- Authenticate when prompted
	- *You'll know it is running as expected when you see the line `press ctrl+d to stop `*
4. In **terminal 2**, start your `twig` on the pcap file's network by running the command `./twig -i 172.31.128.2_24`
	- *this gives your twig an interface with IP `172.31.128.2` on the network `172.31.128.0/24`*
5. In **terminal 3**, run `./socket_time 172.31.128.2`, then press `Ctrl+c` to stop `socket_time`.
	- *This is to get around the issue of the first packet being ignored...* 
6. In **terminal 3**, move to the udpping directory with `cd udp_ping`
7. In **terminal 3**, compile udpping (if not done already) with `make`
8. In **terminal 3**, run the command `udpping 172.31.128.2` 

#### Shutdown

For shutting down, there is a known issue witht he shim, so follow these steps to shut down cleanly:
1. In **terminal 3**, run `ping 172.31.128.2`
	- *This will give packets to the shim and let it check for the shutdown signal. (See [Issues](README.md#issues-and-clarifications-ongoing-updates).)*
2. In **terminal 1**, press `Ctrl+d`
	- *`test_twig.sh` should stop running within a second, when `shim.py` recieves a packet.*
3. In **terminal 3**, press `Ctrl+c`
	- *`ping` should stop immediately.*
3. In **terminal 2**, press `Ctrl+c`
	- *`twig` should stop immediately*

#### Expected Results

The output of the `udpping` client from **step 8** is what matters. 

Example **Good** output in **terminal 3** from **step 8**:
```
sspringer-fedora-udp_ping: ./udpping 172.31.128.2
Sending 1000 udp echo requests of size 50 to 172.31.128.2 on port echo
 100 200 300 400 500 600 700 800 900


time spent waiting for echos to return (in milliseconds):
# sent  # rcvd  # late       total        min       max       avg
------  ------  ------  -----------  --------  --------  --------
  1000    1000       0    21688.166    11.206    49.648    21.688 
0.00% packet loss
```

Key components to make sure are correct:
- 0.00% packet loss

##### Common issues and causes:

- Similar to ICMP Ping, you may have dups or missing packets, I recommend debugging those on the ICMP side when possible.
- Debugging missing packets may be simpler with lower numbers, which canbe achieved by specifying how many packets to send with the `-c` option to udpping.		
	- Then check the `172.31.128.0.dmp` file with wireshark.
	- Most likely cause for no responses is a bad checksum.



### Test 3 (socket_time)

#### Procedure
1. Open 3 terminal windows, each with this repository as their working directory.
2. Create a symbolic link to your twig program in the local directory by running the following command in **terminal 1**: `ln -s <your twig directory>/twig ./twig `
	- *Make sure to replace `<your twig directory>` with the directory your twig program is present in, and ensure you have a binary named `twig` in that directory.*
3. In **terminal 1**, run `./twig_test.sh`
	- Authenticate when prompted
	- *You'll know it is running as expected when you see the line `press ctrl+d to stop `*
4. In **terminal 2**, start your `twig` on the pcap file's network by running the command `./twig -i 172.31.128.2_24`
	- *this gives your twig an interface with IP `172.31.128.2` on the network `172.31.128.0/24`*
5. In **terminal 3**, run `./socket_time 172.31.128.2`, then press `Ctrl+c` to stop `socket_time`.
	- *This is to get around the issue of the first packet being ignored...* 
6. In **terminal 3**, compile socket_time (if not done already) with `make socket_time`
7. In **terminal 3**, run the command `./socket_time 172.31.128.2` 

#### Shutdown

For shutting down, there is a known issue witht he shim, so follow these steps to shut down cleanly:
1. In **terminal 3**, run `ping 172.31.128.2`
	- *This will give packets to the shim and let it check for the shutdown signal. (See [Issues](README.md#issues-and-clarifications-ongoing-updates).)*
2. In **terminal 1**, press `Ctrl+d`
	- *`test_twig.sh` should stop running within a second, when `shim.py` recieves a packet.*
3. In **terminal 3**, press `Ctrl+c`
	- *`ping` should stop immediately.*
3. In **terminal 2**, press `Ctrl+c`
	- *`twig` should stop immediately*

#### Expected Results

The output of the `socket_time` client from **step 7** is what matters. 

Example **Good** output in **terminal 3** from **step 7**:
```
sspringer-fedora-Twig-tools: ./socket_time 172.31.128.2
The time on 172.31.128.2 is 0xed9296eb
```

Key components to make sure are correct:
- The output timestamp is in big-endian (network byte order) hex, complies with the  `1 Jan 1900` timestamp specified by the RFC, and when converted to human readable format is close to the current time.
	- You can convert this to human readable format using the following steps:
		- Convert to local byte order (little-endian in this example): `0xeb9692ed` 
		- Convert to decimal: `3952513773`
		- Subtract the time offset to convert from the `1900` epoch to the unix standard `1970` epoch timestamp: `1743524973`
		- Convert unix timestamp to human readable format `2025-04-01 12:29:33` 
	- Then just check that the time it converts to is within a few minutes of the current time. (*if something is wrong it'll usually be years wrong, not minutes wrong*) 


##### Common issues and causes:

- Time appears incorrect despite a correct conversion method
	- usually caused by a failure to convert the timestamp on to big endian within `twig`, or a failure to convert from the unix standard `1970` epoch to the [RFC 868](https://www.rfc-editor.org/rfc/rfc868.html) `1900` epoch

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

## udpping
udpping is a basic client for the udp echo protocol.

This client was written by Dr. Shawn Ostermann.

The source code is included in the subdirectory `udp_ping`

To compile, run `make` in the `udp_ping` subdirectory.

By default, testing with `udpping`  will send 1000 packets, and give a summary of results at the end, presuming not all of them were discarded or lost.

`udpping -` will output usage with more details on how to refine your testing.

Testing details to follow in [Testing](README.md#testing)


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

To close down the shim this script starts, simply use `ctrl+d` or `ctrl+c` in the terminal it is running in*.

(*) - see [Issues and Clarifications](README.md#issues-and-clarifications-ongoing-updates)

If `-w` is provided as an additional argument to this script when started, it will establish a wireshark session which live-captures from the network pcap file. NOTE: this session doesnt close automatically when you kill the shim, it will need to be closed manually.

If your default interface contains spaces, edit the script to have the name already specified or enable it to take the interface as an argument. Comments in the script identify where to do this.

To use a new network address from the default, edit the script to use your chosen network (non-public IPs only) or enable it to take the network as an argument. Comments in the script identify where to do this.

**NOTE: This script will prompt for password since you need root to run the shim.**

This script has all the requirements to run shim, and additionally uses lots of BASH specific expansions such as the arithmetic expansion notation `$(( <expr> ))`.


## docker_test.sh

### Description

This script 
- Builds a docker image with all the prerequisites to run the shim
- Constructs a docker network to host the shim container
- Adds an ip route to direct traffic for the shim to the docker container
- Starts the docker container using the image it made, mounting the local directory, and starting the `twig_test.sh` script which runs the shim. 
- Removes the container on exit
- **IF PROVIDED WITH `--rm`**, it additionally: 
	- Removes the created docker network on exit
	- Removes the added ip route on exit

To close down the shim and container this script starts, simply use `ctrl+d` or `ctrl+c` in the terminal it is running in*.

(*) - see [Issues and Clarifications](README.md#issues-and-clarifications-ongoing-updates)

If `--rm` is provided as an additional argument to this script when started, it will remove the docker network and ip route it creates on exit.

To use new parameters from the default, edit the script to use your chosen values, but be warned that modifying any of the network addresses will require changing the addresses in all commands which reference them.

**NOTE: This script will prompt for password since you need root to make ip routes**


## dockershim.sh

### Description

This script 
- Starts a docker container using the image it made, mounting the local directory, and starting the `twig_test.sh` script which runs the shim. 
- Removes the container on exit


To close down the shim and container this script starts, simply use `ctrl+d` or `ctrl+c` in the terminal it is running in*.

(*) - see [Issues and Clarifications](README.md#issues-and-clarifications-ongoing-updates)

To use new parameters from the default, edit the script to use your chosen values, but be warned that modifying any of the network addresses will require changing the addresses in all commands which reference them.

This script is provided for use mostly for cases where the shim may need restarted frequently and it is easier to manually do the docker image, docker network, and ip route setup and shutdown than to let the `docker_test.sh` script do it for you. Most of these cases are debugging for now, but once your twig becomes a shrub router, this will be more likely to be used. (and there will be additional instructions to go along with it.) 

## cleandocker.sh

### Description

this script cleans up everything made by docker. specifically it deletes the image and network made by `docker_test.sh` or `dockershim.sh`

if you change values in either of those scripts, you must also change the values in this script for it to clean correctly.

## CHAIN.sh

### Description

`CHAIN.sh` sets up a chain of 5 routers connected at one end with the shim to the real network. The topology looks something like this:

<img src="./CHAIN.sh.drawio.svg">

To actually use this script and test your program using it, there are several changes to the [Running Overview](README.md#running-overview)/[Running with Docker](README.md#running-with-docker) though the overall idea is the same.

The following is a procedure to run using this script.

### Running without Docker

#### Setup

We will start by establishing routes from the *ping machine* to the twigs on the *twig machine*. First we need the IP address of the *twig machine*, which can be obtained using the `ip` command on the *twig machine*. 

I.e. 
```c
twig: ip r | grep default
default via 192.168.1.1 dev wlp170s0 proto dhcp src 192.168.1.42 metric 600 
```
> Here, we see the address for our default interface is `192.168.1.42`

**Your next hop will likely be different, make sure to use *your* next hop IP instead of `192.168.1.42` in the commands that follow.**

Then on the *ping machine* we establish routes that will direct traffic intended for the twigs to our `twig machine`.

I.e.
```c
ping: sudo ip r add 172.31.128.0/24 via 192.168.1.42
ping: sudo ip r add 172.31.1.0/24 via 192.168.1.42
ping: sudo ip r add 172.31.2.0/24 via 192.168.1.42
ping: sudo ip r add 172.31.3.0/24 via 192.168.1.42
ping: sudo ip r add 172.31.4.0/24 via 192.168.1.42
ping: sudo ip r add 172.31.5.0/24 via 192.168.1.42
```

Now we can start the shim and `twig`s on the *twig machine* using 
```
twig: ./twig_test.sh
```
and in another terminal
```
twig: ./CHAIN.sh
```



**NOTE: you will need to wait a few seconds to let RIP establish routes, and your default route argument to shrub will need to be functional.**

---

Finally we can send traffic from our *ping machine*:
```
ping: ping 172.31.4.254
```
```
ping: udpping 172.31.4.254
```
```
ping: socket_time 172.31.4.254
```
```
ping: traceroute 172.31.4.254
```

**NOTE: traceroute may be a little misleading, the first router seems not to be included in the results because forwarding by the shim doesnt reduce ttl.**


#### Repeat Running

You can run `ping`, `traceroute`, `udpping`, or `socket_time` on the *ping machine* repeatedly without adverse effects aside from the growing pcap file on the *twig machine*.

If you need to restart your CHAIN, kill the twigs using the command in shutdown, and restart your shim as well.

#### Shutdown

To fully shut down all components of this project and return everything to the original state, we need to do the following:

- Kill the shim script
- In the terminal where you ran the `CHAIN.sh` script, run
```ps | grep twig | awk '{ print $1 }' | xargs kill``` 
	- if you are using a name for your program other than `twig`, change the grep argument to match.
- On the *ping machine*, run
```
sudo ip r del 172.31.128.0/24
sudo ip r del 172.31.1.0/24
sudo ip r del 172.31.2.0/24
sudo ip r del 172.31.3.0/24
sudo ip r del 172.31.4.0/24
sudo ip r del 172.31.5.0/24
```



### Running with Docker


This new version of the shim can only communicate with remote hosts, it cannot do loopback connections. So docker allows us to abstract this and do loopback connections in a way that appears as a remote connection to the shim.
Additionally, docker allows us to have a strict environment and allow better portability across systems.

#### Setup

For initial setup, we will build the necessary components to run our shim in docker and have routes to get to it appropriately. 

To begin, open three terminals with this repository as the working directory.

Start by running the `dockershim.sh` script:

```c
./dockershim.sh
```

Now, in a separate temrinal window, start your CHAIN:

```c
./CHAIN.sh -d=172.31.127.254
```
**NOTE: if you change the ip your docker container uses in `dockershim.sh`, change the -d= argument to `CHAIN.sh` to match.**


Finally we can send traffic from another terminal window:
```
ping 172.31.4.254
```
```
udpping 172.31.4.254
```
```
socket_time 172.31.4.254
```
```
traceroute 172.31.4.254
```

**NOTE: traceroute may be a little misleading, the first router seems not to be included in the results because forwarding by the shim doesnt reduce ttl.**


#### Repeat Running

You can run `ping`, `traceroute`, `udpping`, or `socket_time` repeatedly without adverse effects aside from the growing pcap file.

If you need to restart your CHAIN, kill the twigs using the command in shutdown, and restart your shim as well.

#### Shutdown commands

To clean up, you will need to run the docker cleanup script and remove the ip routes added by the dockershim script.

Additionally you will need to terminate all of the twigs the CHAIN started.
If you are using a name for your program other than `twig`, change the grep argument to match.

```c
ps | grep twig | awk '{ print $1 }' | xargs kill

./cleandocker.sh

sudo ip route del 172.31.128.0/24
sudo ip route del 172.31.1.0/24
sudo ip route del 172.31.2.0/24
sudo ip route del 172.31.3.0/24
sudo ip route del 172.31.4.0/24
sudo ip route del 172.31.5.0/24
```

