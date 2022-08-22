# read log file and output results
# Run as: ruby analyze-log.rb log.jsonl
# OR for a particular UUID
# ruby analyze-log.rb log.jsonl efdca7f8-9c6b-47c1-8911-f50e1e426384

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

# Data structures to keep track of Websocket RTT results and ZeroTrace Results
ztResult = Struct.new(:finalHop, :rtt)
ws = Hash.new
zerotrace = Hash.new

ip = File.open(ARGV[0], 'r')
uuidReq = ARGV[1]
ip.each_line do |line|
    json = JSON.parse(line.strip)
    uuid = json["UUID"]
    if json["latencies"] != nil
        arr = json["latencies"]
        median = getMedian(arr)
        ws[uuid] = median
    elsif json["HopData"] != nil
        hops = json["HopData"]
        hopVal, data = getZeroTracedata(hops)
        next if hopVal == 0
        zerotrace[uuid] = ztResult.new(hopVal, data["RTT"])
    end
end

# Print the absolute difference between zerotrace's last hop RTT (network layer) and median websocket RTT (application layer)
# Either for the given uuid or for all experiments
if uuidReq != nil
    ztRTT = zerotrace[uuidReq][:rtt]
    wsRTT = ws[uuidReq]
    diff = (ztRTT - wsRTT).abs
    puts "Difference in Websocket RTT and ZeroTrace RTT for UUID: " + uuidReq + " is: " + diff.to_s
else
    zerotrace.each do |uuid, zt|
        next if zt[:rtt] == nil
        diff = (zt[:rtt] - ws[uuid]).abs
        puts diff
    end
end