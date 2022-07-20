# Script to run the evaluation of the 0trace method

On sudo, run: `./sync-wrapper.sh` 
It needs:
- `inputs/atlas-ip-probeid.txt` which has a newline-delimited file containing comma-separated RIPE Atlas Probe IPs and the corresponding probe-ids
- `outputs/` directory
- [RIPE Atlas CLI toolkit](https://ripe-atlas-tools.readthedocs.io/en/latest/installation.html) installed. We use the `asslcert` measurement command which is short for `ripe-atlas measure sslcert`
    - Must [configure the RIPE Atlas CLI toolkit](https://ripe-atlas-tools.readthedocs.io/en/latest/quickstart.html#creating-a-measurement) to use your API key