# Script to run an ICMP pinger code

To run: `go run batched-icmp.go --inputfile iplist.txt --outputfile icmp-output.jsonl`

where input file `iplist.txt` is a newline delimited list of IPs to which you are interested in sending ICMP pings, it outputs JSON lines.
