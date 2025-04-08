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


