# create new file, keeping track of uuid and final RTT diff
# Run as: ruby analyze-log.rb log.jsonl analyzed-data.jsonl

require 'json'

def getMin(arr)
    sorted = arr.sort
    return sorted[0]
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
ztResult = Struct.new(:finalHop, :finalIP, :rtt)
ws = Hash.new
zerotrace = Hash.new
type = Hash.new
icmpStat = Hash.new
clientIP = Hash.new

ip = File.open(ARGV[0], 'r')
op = File.open(ARGV[1], 'w')
ip.each_line do |line|
    json = JSON.parse(line.strip)
    uuid = json["UUID"]
    if json["Contact"] != nil
        type[uuid] = json["ExpType"]
    elsif json["IcmpPing"] != nil and json["IcmpPing"]["MinRtt"] != 0
      icmpStat[uuid] = json["IcmpPing"]["MinRtt"].round(3)
    elsif json["latencies"] != nil
        arr = json["latencies"]
        clientIP[uuid] = json["IP"]
        min = getMin(arr)
        ws[uuid] = min.round(3)
    elsif json["HopData"] != nil
        hops = json["HopData"]
        hopVal, data = getZeroTracedata(hops)
        next if hopVal == 0
        zerotrace[uuid] = ztResult.new(hopVal, data["IP"], data["RTT"].round(3))
    end
end

diffStruct = Struct.new(:UUID, :Type, :WSMinRTT, :ICMPMinRTT, :ZeroTraceRTT, :ZeroTraceHop, :ClientReached, :RTTDiff)
darr = Array.new
zerotrace.each do |uuid, zt|
        next if zt[:rtt] == nil
        if icmpStat[uuid] != nil 
          diff = (icmpStat[uuid] - ws[uuid]).abs.round(3)
        else
          diff = (zt[:rtt] - ws[uuid]).abs.round(3)
        end
        clientReached = (clientIP[uuid] == zt[:finalIP]) 
        darr << diffStruct.new(uuid, type[uuid], ws[uuid], icmpStat[uuid], zt[:rtt], zt[:finalHop], clientReached, diff)
end
darr = darr.sort_by{|v| v[:RTTDiff]}

darr.each do |str|
    op.puts str.to_h.to_json
end