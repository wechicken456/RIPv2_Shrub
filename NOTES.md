# Build instruction
```bash
cd src
make
cd ..
# follow testing instructions in README.md
```


# Byte order

The most confusing part so far.

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



