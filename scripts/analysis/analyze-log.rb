# read log file and output results
# Run as: ruby analyze-log.rb log.jsonl
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

# Data structures to keep track of Websocket RTT results and ZeroTrace Results
ztResult = Struct.new(:finalHop, :rtt)
ws = Hash.new
zerotrace = Hash.new

ip = File.open(ARGV[0], 'r')
ip.each_line do |line|
    json = JSON.parse(line.strip)
    uuid = json["UUID"]
    if json["latencies"] != nil
        arr = json["latencies"]
        median = getMedian(arr)
        ws[uuid] = median
    elsif json["HopData"] != nil
        hops = json["HopData"]
        hopVal = 0
        currData = ""
        hops.each do |hopNum, data|
            # find the furthest hop for which we obtained an RTT value
            if hopVal < hopNum.to_i and data["IP"] != ""
                hopVal = hopNum.to_i
                currData = data
            end
        end
        next if hopVal == 0
        zerotrace[uuid] = ztResult.new(hopVal, currData["RTT"])
    end
end

# Print the absolute difference between zerotrace's last hop RTT (network layer) and median websocket RTT (application layer)
zerotrace.each do |uuid, zt|
    next if zt[:rtt] == nil
    diff = (zt[:rtt] - ws[uuid]).abs
    puts diff
end