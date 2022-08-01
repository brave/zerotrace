# Feed in the json file extracted from https://ftp.ripe.net/ripe/atlas/probes/archive/2022/07/
# I downloaded: 20220719.json.bz2, and extracted it
# run script as: ruby parse-ripe-probe-data.rb 20220719.json list-of-probes.jsonl atlas-ip-probeid.txt
require 'json'

def checktags(json)
	x = json["tags"]
	if x.include?("home")
		return true
	end
	return false	
end

ip = File.open(ARGV[0], 'r')
op = File.open(ARGV[1], 'w')
op2 = File.open(ARGV[2], 'w')

ipHash = Hash.new
ip.each_line do |line|
	json_list = JSON.parse(line)
	json_list.each do |json|
		if json["address_v4"] != nil and json["status_name"] == "Connected" and checktags(json)	
			op.puts JSON.dump(json)
			op2.puts json["address_v4"] + "," + json["id"].to_s
		end
	end
end

=begin
Example probe that passes the checks in this program: 
	{
	"id": 1000,
	"address_v4": "144.134.116.134",
	"address_v6": "2001:8003:7105:c200:220:4aff:fec7:b000",
	"asn_v4": 1221,
	"asn_v6": 1221,
	"prefix_v4": "144.132.0.0/14",
	"prefix_v6": "2001:8000::/20",
	"is_anchor": false,
	"is_public": true,
	"status": 1,
	"status_since": 1658106332,
	"first_connected": 1307310425,
	"total_uptime": 307376881,
	"tags": [
		"system-ipv6-stable-1d",
		"system-ipv4-stable-1d",
		"system-resolves-aaaa-correctly",
		"system-resolves-a-correctly",
		"system-ipv6-works",
		"system-ipv4-works",
		"system-ipv4-capable",
		"system-ipv4-rfc1918",
		"system-ipv6-capable",
		"cable",
		"home",
		"nat",
		"ipv4",
		"system-v1"
	],
	"country_code": "AU",
	"latitude": -27.4225,
	"longitude": 153.0275,
	"day": "20220719",
	"probe": "https://atlas.ripe.net/api/v2/probes/1000/",
	"status_name": "Connected"
	}
=end