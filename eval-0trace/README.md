# Script to run the evaluation of the 0trace method

On sudo, run: `./sync-wrapper.sh` 

h/t: The script `0trace.sh` and all its components (`sendprobe.c`, `types.h`) was developed by Michal Zalewski, [documented in Bugtraq](https://lwn.net/Articles/217023/), and was [downloaded from here](http://lcamtuf.coredump.cx/soft/0trace.tgz). The script `usleep.c`, necessary for 0trace to run, was obtained [from aldeid/wiki](https://www.aldeid.com/wiki/0trace).

I made a change to `sendprobe.c` to increase the max TTL hop from `30` --> `64`

It needs:
- `inputs/atlas-ip-probeid.txt` which has a newline-delimited file containing comma-separated RIPE Atlas Probe IPs and the corresponding probe-ids
- `outputs/` directory
- [RIPE Atlas CLI toolkit](https://ripe-atlas-tools.readthedocs.io/en/latest/installation.html) installed. We use the `asslcert` measurement command which is short for `ripe-atlas measure sslcert`
    - Must [configure the RIPE Atlas CLI toolkit](https://ripe-atlas-tools.readthedocs.io/en/latest/quickstart.html#creating-a-measurement) to use your API key