#!/bin/bash

umask 077

T=`mktemp "$HOME/.0trace-XXXXXX"`

if [ "$2" = "" ]; then
  echo "Usage: $0 iface target_ip [ target_port ]" 1>&2
  exit 1
fi

if [ ! -x /bin/usleep ]; then
  echo "[-] /bin/usleep not found on this system, sorry." 1>&2
  exit 1
fi

if [ ! "`uname`" = "Linux" ]; then
  echo "[-] WARNING: Only Linux is believed to work fine with this utility." 1>&2
fi

make sendprobe >/dev/null
test -f ./sendprobe || exit 1

echo "0trace v0.01 PoC by <lcamtuf@coredump.cx>"

RULE="(tcp[13] & 0x17 == 0x10) and src host $2"
test "$3" = "" || RULE="$RULE and src port $3"

echo "[+] Waiting for traffic from target on $1..."

/usr/sbin/tcpdump -c 1 -s 200 -S -q -i "$1" -n -x "$RULE" >"$T" 2>/dev/null

if [ ! -s "$T" ]; then
  echo "[-] Something went wrong with tcpdump (check parameters)."
  rm -f "$T"
  exit 1
fi

echo "[+] Traffic acquired, waiting for a gap..."

WAITING=0
WAITTIME=0

while [ "$WAITTIME" -lt "80" ]; do
  /usr/sbin/tcpdump -c 1 -s 200 -S -q -i "$1" -n -x "$RULE" >"$T-2" 2>/dev/null &
  TPID="$!"
  usleep 100000

  while kill -0 "$TPID" 2>/dev/null; do
    WAITING=$[WAITING+1]
    if [ "$WAITING" -gt "20" ]; then
      kill "$TPID" 2>/dev/null
      break
    fi
    usleep 100000
  done
  
  test -s "$T-2" || break
  WAITING=0
  cat "$T-2" >"$T"
  WAITTIME=$[WAITTIME+1]
  
done

if  [ "$WAITTIME" -ge "80" ]; then
  echo "[-] Couldn't find a sufficient period of no activity."
  exit 1
fi

cat "$T" | head -3 | tail -1 | sed 's/0x[0-9]*:/ /g' | cut -b25- >"$T-2"
read A1 A2 S1 S2 <"$T-2"
cat "$T" | head -1 | sed 's/IP //' | cut -d' ' -f2,4 | sed  's/\.\([0-9]*\)[: ]/ \1 /g' >"$T-2"
read DADDR DPORT SADDR SPORT <"$T-2"
rm -f "$T-2"

SEQ=`printf "%u" 0x$S1$S2`
ACK=`printf "%u" 0x$A1$A2`

echo "[+] Target acquired: $SADDR:$SPORT -> $DADDR:$DPORT ($SEQ/$ACK)."

echo "[+] Setting up a sniffer..."

/usr/sbin/tcpdump -l -s 200 -S -q -i "$1" -n -x "icmp or ($RULE)" >"$T" 2>/dev/null &
TPID="$!"

echo "[+] Sending probes..."

./sendprobe $SADDR $DADDR $SPORT $DPORT $SEQ $ACK
sleep 2
kill "$TPID" 2>/dev/null

echo 
echo "TRACE RESULTS"
echo "-------------"

cat "$T" | sed 's/ IP//g;s/^[ 	]*0x[0-9]*: //g' | grep -vE '45.0 00' | grep -iA1 'time.excee' | \
  grep -vE '^--' | cut -d' ' -f2 | \
  sed 's/\([0-9a-f][0-9a-f]\)[0][0]$/\1/g' | \
  awk '{if (NR%2) {SAVE=$0} else {print $0 " " SAVE}}' | \
  grep -v '[0-9a-f][0-9a-f][0-9a-f][0-9a-f]' | \
  while read -r num dat; do echo "$[0x$num] $dat"; done | sort -n -u

if grep -qF ': tcp 0' "$T"; then
  echo "Target reached."
else
  echo "Probe rejected by target."
fi

echo

rm -f "$T"

exit 1 

