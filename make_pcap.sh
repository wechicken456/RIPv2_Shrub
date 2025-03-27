#!/bin/bash

# Define pcap header values in hexadecimal
endian=""
if [[ $(lscpu | grep -i 'little endian' | wc -l) -eq 1 ]]; then
	magic_number="d4c3b2a1" # Little-endian
	major_version="0200"
	minor_version="0400"
	time_zone_offset="00000000"
	timestamp_accuracy="00000000"
	snapshot_length="10270000" # 10000
	network_link_type="01000000" # Ethernet
	endian="little endian" 
else
	magic_number="a1b2c3d4" # Big-endian
	major_version="0002"
	minor_version="0004"
	time_zone_offset="00000000"
	timestamp_accuracy="00000000"
	snapshot_length="00002710" # 10000
	network_link_type="00000001" # Ethernet
	endian="big endian"
fi

# Combine header values
header_hex="$magic_number$major_version$minor_version$time_zone_offset$timestamp_accuracy$snapshot_length$network_link_type"

# Convert hex string to binary and write to file
echo "$header_hex" | xxd -r -p > "$1"

echo "Pcap header ($endian) written to $1"