# PCAP_Parser


This program analyzes captured network traffic (pcaps) for indicators of malicious activity
It currently supports parsing HTTP, DNS and TCP traffic
USAGE:  + "python pcapparser.py [PATH TO PCAP file] + [VirusTotal API key] + [Number corresponding to desired traffic]
1. HTTP requests
2. DNS queries
3. TCP connections
4. All of the above
5. TCP Payload data
6. UDP Payload data

Excluding TCP/UDP payload data from #4, for performance reasons. Performance depends on the number of packets present in the pcap file
