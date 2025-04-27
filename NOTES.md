# Build instruction
```bash
cd src
make
cd ..
# follow testing instructions in README.md
```


# Byte order

The most confusing part so far.

Note that throughout the flow of the program, IPv4 addresses are in NETWORK byte order. It is up to each individual function to convert it to host byte order if it needs to. It's just a matter of convenience since we don't really change IP addresses in a packet (we mostly just swap the src and dst).

Pcap FILE header and Pcap PACKET header are in sender's machine endianness, while all the actual networking fields are in NETWORK byte order (big-endian).


When to convert:

1. When reading packet fields: Convert from network order to host order = `ntohs`
2. When writing packet fields: Convert from host order to network order = `htons`.
3. When dealing with PCAP headers: Check the magic number and convert if necessary.

For **checksums**: 

1. Calculation: the checksum is calculated **AFTER** converting all other fields into NETWORK BYTE ORDER. Then the checksum ITSELF is stored, without caring about endianness. 
2. Verification: verify checksum BEFORE converting anything host byte order. i.e. Leave everything alone and check the checksum.
3. ICMP checksum is calculated over the ENTIRE ICMP packet, not just the header.
4. IPv4 checksum is calculated over ONLY the IPv4 HEADER.
5. UDP checksum is calculated from pseudo IPv4 header, UDP header, and UDP data. [RFC](https://www.ietf.org/rfc/rfc768.txt)

# Header lengths

pcap_pkthdr:
```C
struct pcap_pkthdr {
	bpf_u_int32 ts_secs;		/* time stamp */
	bpf_u_int32 ts_usecs;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};
```

IPv4 header: 
```C
struct ipv4_hdr {
    uint8_t 	version_ihl;    
    uint8_t 	type_of_service;
    uint16_t 	total_len; 
    uint16_t 	frame_ident;
    uint16_t 	fragment_offset;
    uint8_t 	time_to_live;
    uint8_t 	next_proto_id;
    uint16_t 	hdr_checksum;
    uint8_t 	src_addr[4];
    uint8_t 	dst_addr[4];
};
```

`total_len` = ipv4 header length + `data`, where `data` is the beginning of the packet for the next layer protocol (ICMP/TCP/UDP/etc).

# ICMP packets

RFC: https://datatracker.ietf.org/doc/html/rfc792

The data received in the echo message must be returned in the echo reply message!



# Shrub dev notes


For each shrub instance (program), spawn a reading thread for each interface. This thread will read packets from that interface and write reply packets - which can go to other interfaces. 

=> Use mutexes to guard the write_pcap() function.

**Shared memory** among threads:The RIP table (`rip_cache_v4`), and the `interfaces` array.
**Thread Local Storage**: the `iov`s.

As per the testing instruction, and the nature of the [shim.py](./shim.py), hardcode the MAC source address for EVERY reply packet to start with `5e:fe`.

## Mutexes

Use [pthread_mutex_lock](https://stackoverflow.com/a/40880980) before any read/write from an interface's file descriptor.

## RIP
As per the RFC, first, check if a packet is from and to port 520.

Then, check if the IPv4 source is from one of our interfaces. If it is not, ignore it. This can be done by looping through the global `interfaces` accessible by all threads.

Section 3.7 of RFC 2453 states:

> The special address 0.0.0.0 is used to describe a default route.  A default route is used when it is not convenient to list every possible network in the RIP updates, and when **one or more closely- connected routers in the system are prepared to handle traffic to the networks that are not listed explicitly. **

=> We should advertise the default route, with the next hop being our address.

## `outgoing_interface_idx` vs `thread_interface_idx` vs `meant_for_interface_idx`

All are thread local variables.

By default, `outgoing_interface_idx` = `meant_for_interface_idx` = `thread_interface_idx`.
where `thread_interface_idx` is the interface the thread is responsible for reading pcap packets from and write to.

However, say we have 2 interfaces `172.31.1.254` and `172.31.2.253`. When a packet is sent to us on `172.31.2.253`, but we received (read) it on `172.31.1.254`, we should use the same IP address (`172.31.2.253`) in our response packet, but we shouldn't immediately conclude that we should write the response packet back to the interface we read it from (`172.31.1.254`).

This is because there could be more efficient routes to get back to the source.
Hence, we should check the RIP table and find the interface to write the response back to, which we we will assign to `outgoing_interface_idx`.

All protocol layers will use `outgoing_interface_idx` to set the appropriate source addresses for their packets.
