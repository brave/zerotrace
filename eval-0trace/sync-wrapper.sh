#Run this script as sudo: 0trace.sh needs sudo access
#!/bin/bash
export PATH=$PATH:/usr/local/go/bin
ulimit -n 10000
for ipprobe in $(cat inputs/atlas-ip-probeid.txt); do
	echo "ip,probe $ipprobe"
	IFS=, read -r ip probe <<< $ipprobe
	./0trace.sh eth0 $ip > outputs/${ip}.txt &
	asslcert --target test.reethika.info --from-probes=$probe --no-report
	sleep 30s
	pkill 0trace.sh
	go run parse-each.go --outputfile=output-run.jsonl --evalrttfile=eval-run.jsonl --tracefile=outputs/${ip}.txt
done
