# lookup experiments by uuid
# Run as: ruby lookup-by-uuid.rb log.jsonl efdca7f8-9c6b-47c1-8911-f50e1e426384
require 'json'

def getMedian(arr)
    sorted = arr.sort
        middle = arr.length / 2 
        if arr.length.even?
            return sorted[middle-1, 2].sum / 2.0
        else
            return sorted[middle]
        end
end

def getZeroTracedata(hops)
    hopVal = 0
    currData = ""
    hops.each do |hopNum, data|
        # find the furthest hop for which we obtained an RTT value
        if hopVal < hopNum.to_i and data["IP"] != ""
            hopVal = hopNum.to_i
            currData = data
        end
    end
    return hopVal, currData
end

ip = File.open(ARGV[0], 'r')
uuidReq = ARGV[1]
puts "Looking for UUID: " + uuidReq + "....."
found = false
ip.each_line do |line|
    json = JSON.parse(line.strip)
    if json["UUID"] == uuidReq
        contact = json["Contact"]
        icmp = json["IcmpPing"]
        ws = json["latencies"]
        zt = json["HopData"]
        if contact != nil
            puts "Email:                    " +  contact
            puts "Experiment Type:          " + json["ExpType"]
        elsif icmp != nil
            puts "IP address:               " + icmp["IP"]
            puts "AvgRTT:                   " + json["AvgIcmpStat"].to_s
        elsif ws != nil
            puts "Websocket Latencies:      " + ws.to_s
            puts "Median WS RTT:            " + getMedian(ws).to_s
        elsif zt != nil 
            found = true
            lastHop, data = getZeroTracedata(zt)
            puts "0trace Result, Last Hop:  " + lastHop.to_s
            puts "0trace Result, Last IP:   " + data["IP"].to_s
            puts "0trace Final RTT:         " + data["RTT"].to_s
        end
    elsif found == true
        break
    end
end
