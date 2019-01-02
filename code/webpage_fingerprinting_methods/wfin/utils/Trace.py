from __future__ import division
import sys
import Utility, random, math
import numpy as np
from Packet import Packet
from TCPConnection import TCPConnection
from collections import defaultdict

class Trace(object):
    def __init__(self, traceId, webId):
        self.traceId = traceId
        self.webId = webId
        
        self.tcpCons = []
        self.startTime = np.inf
        self.endTime = 0
        self.inBytesperCon = defaultdict(float)
        self.outBytesperCon = defaultdict(float)
        
        self.portBytes = defaultdict(list)
        self.timeInfoPerTcp = []
        
#         self.inPacketsNum = 0
#         self.outPacketsNum = 0
    
    def addTcpCon(self, tcp):
        if tcp.getPacketNum() == 0: return
        
        sTime, eTime = tcp.getTransTime()
        self.startTime = min(self.startTime, sTime)
        self.endTime = max(self.endTime,eTime)
        
        index = tcp.getTimeIndex()
        if tcp.totalBytes(Packet.Incoming) != 0 or tcp.totalBytes(Packet.Outgoing) != 0:
            self.inBytesperCon[index] = tcp.totalBytes(Packet.Incoming)
            self.outBytesperCon[index] = tcp.totalBytes(Packet.Outgoing)
            self.timeInfoPerTcp.append(index)
            self.timeInfoPerTcp = sorted(self.timeInfoPerTcp)
            self.tcpCons.append(tcp)
        
    def getWebId(self):
        return self.webId
    
    def getTraceId(self):
        return self.traceId
    
    def getTraceTime(self):
        return self.startTime, self.endTime
    
    def reorderTCPCons(self):
        timeTCP = {}
        for tcp in self.tcpCons:
            timeTCP[tcp.getTimeIndex()] = tcp
        
        self.tcpCons = []
        for time in sorted(timeTCP.keys()):
               self.tcpCons.append(timeTCP[time])
            
    def getTcpCons(self):
        return self.tcpCons
    
    def getTcpConsNum(self):
        return len(self.tcpCons)

    def getBytesTCP(self, TCPNum=None, direction=None):
        bytesTCP = []
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
        
        for timeIndex in self.timeInfoPerTcp[:TCPNum]:
            if not direction:
                bytesTCP.append(self.inBytesperCon[timeIndex]+self.outBytesperCon[timeIndex])
            elif direction == Packet.Incoming:
                bytesTCP.append(self.inBytesperCon[timeIndex])
            else:
                bytesTCP.append(self.outBytesperCon[timeIndex])

        return bytesTCP
    
    ## per second
    def getPacketNumPerSec(self, binSize=1000, TCPNum=None, PacketNum=None):
        t = []
        it = []
        ot = []
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        for tcp in self.getTcpCons()[:TCPNum]:
            packets = tcp.getPackets()
            if PacketNum:
                packets = packets[:PacketNum]
                
            for packet in packets:
                time = packet.getTime()
                t.append(time)
                if packet.getDirection() == Packet.Incoming:
                    it.append(time)
                else:
                    ot.append(time)
           
        nums = []
        innums = []
        outnums = []
        
        if len(t) == 0:
            minT=0
            maxT=0
        else:
            minT = min(t)
            maxT = max(t)
            for i in range(min(int(math.ceil((maxT-minT)/binSize)), 60)):
                l_thres = minT+(i*binSize)
                h_thres = l_thres+binSize
                nums.append(len([p for p in t if p>=l_thres and p<h_thres]))
                innums.append(len([p for p in it if p>=l_thres and p<h_thres]))
                outnums.append(len([p for p in ot if p>=l_thres and p<h_thres]))
        
        for i in range(min(int(math.ceil((maxT-minT)/binSize)), 60),60):
            nums.append(0)
            innums.append(0)
            outnums.append(0)
            
        return nums, innums, outnums
            
    def getPacketNum(self,TCPNum=None,PacketNum=None):
        packetNum = []
        inPacketNum = []
        outPacketNum = []
        inPacketNumRatio = []
        
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for TCP in self.getTcpCons()[:TCPNum]:
            packets = TCP.getPacketOrder()
            if PacketNum:
                packets = packets[:PacketNum]
                
            totalPacketnum = len(packets)
            inPacketnum = len([i for i in packets if i > 0])
            outPacketnum = len([i for i in packets if i < 0])
            
            packetNum.append(totalPacketnum)
            inPacketNum.append(inPacketnum)
            outPacketNum.append(outPacketnum)
            
            if totalPacketnum != 0: 
                inPacketNumRatio.append(inPacketnum/totalPacketnum)
            else: 
                inPacketNumRatio.append(0)
                
        return packetNum, inPacketNum, outPacketNum, inPacketNumRatio
            
    def packetNumofTCP(self, tcpIndex, direction = None):
        if direction == Packet.Incoming: 
            return self.inPacketNumTCP[tcpIndex - 1] if len(self.inPacketNumTCP) > tcpIndex else 0
        elif direction == Packet.Outgoing: 
            return self.outPacketNumTCP[tcpIndex - 1] if len(self.outPacketNumTCP) > tcpIndex else 0
        else: 
            return self.packetNumTCP[tcpIndex - 1] if len(self.packetNumTCP) > tcpIndex else 0
        
    def getPacketCount(self, rvalue=1, direction=None, TCPNum=None, PacketNum=None):
        packetCount = defaultdict(int)
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for tcp in self.getTcpCons()[:TCPNum]:
            packets = tcp.getPacketOrder()
            if PacketNum:
                packets=packets[:PacketNum] 
            for packet in packets:
                length = Utility.roundToX(packet, rvalue)
                packetCount[length] += 1
                
        return packetCount
    
    def getPacketFrequency(self, rvalue = 1, direction = None):
        self.packetFrequency = defaultdict(float)
        packetCount = self.getPacketCount(direction=direction)
        for length, count in packetCount.items():
            self.packetFrequency[length] = count / np.sum(packetCount.values())
        
        return self.packetFrequency
    
    def getPackets(self, TCPNum=None, PacketNum=None, direction=None):
        packets = []            
        if self.getTcpConsNum() == 1:
            for tcp in self.getTcpCons():
                packets = tcp.getPacketOrder()
        else:
            if not TCPNum:
                TCPNum = self.getTcpConsNum()
           
            tmp = defaultdict(list)
            for TCP in self.getTcpCons()[:TCPNum]:
                if PacketNum:
                    info = TCP.getPackets()[:PacketNum]
                else:
                    info = TCP.getPackets()
                for P in info:
                    length = P.getLength()
                    time = P.getTime()
                    if not direction:
                        if P.getDirection()==Packet.Outgoing:
                            length *= (-1)
                        tmp[time].append(length)
                    elif direction == P.getDirection():
                        tmp[time].append(length)
            
            i = 0
            for time in sorted(tmp.keys()):
                for p in tmp[time]:
                    packets.append(p)
                    i += 1
        return packets
    
    def getPacketInfo(self, TCPNum=None, PacketNum=None):
        packetCount = defaultdict(int)
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        Tol = np.zeros(TCPNum)
        In = np.zeros(TCPNum)
        Out = np.zeros(TCPNum)
        Ratio = np.zeros(TCPNum)
        n = 0
        for TCP in self.getTcpCons()[:TCPNum]:
            for packet in TCP.getPacketOrder(PacketNum=PacketNum):
                packetCount[packet] += 1
                Tol[n] += 1
                if packet > 0: 
                    In[n] += 1
                else:
                    Out[n] += 1
            n += 1
            
        for i in range(TCPNum):
            if Tol[i] != 0:
                Ratio[i] = In[i]/Tol[i]
                
        return packetCount, [Tol, In, Out, Ratio]
    
    def packetSizeinNTCP(self, tcpIndex, packetIndex, direction = None):
        if tcpIndex >= len(self.timeInfoPerTcp): 
            return 0
        index = self.timeInfoPerTcp[tcpIndex]
        try:
            tcpId = ':'.join([index.split(':')[2],index.split(':')[3], index.split(':')[4]])
        except:
            tcpId = int(index.split(':')[-1])
            
        for tcp in self.getTcpCons():
            if tcp.getTcpId() == tcpId:
                if packetIndex >= tcp.getPacketNum(direction): return 0
                index = 0
                for packet in tcp.getPackets():
                    if packet.getDirection() == direction or direction == None:
                        if index == packetIndex: 
                            return packet.getLength() if packet.getDirection() == Packet.Incoming else packet.getLength()*(-1)
                        index += 1

    def calcL1Distance(self, targetDirstribution, direction = None):
        distribution = self.getPacketFrequency(direction)
        keys = list(set(distribution.keys()) | set(targetDirstribution.keys()))
        distance = 0
        for key in keys:
            o = distribution.get(key)
            t = targetDirstribution.get(key)

            if o == None and t == None: continue
            if o == None: o = 0
            if t == None: t = 0

            distance += (o-t) #np.abs(o-t)  
        return distance

    def getMostSkewedDimension(self, targetDirstribution):
        distribution = self.getPacketFrequency()
        keys = distribution.keys()
        worstKey = None
        worstKeyDistance = 0

        for key in keys:
            o = distribution.get(key)
            t = targetDirstribution.get(key)

            if o == None: o = 0
            if t == None: t = 0

            if worstKey == None or np.abs(o-t) > worstKeyDistance: 
                worstKeyDistance = np.abs(o-t)
                worstKey = key 
        return worstKey 
    
    ########## return burstSize, averageHtmlSize, numberOfMarkers ###########  
    def getBurstInfo(self, rvalue=1, burstPair=False):
        self.burstCount = defaultdict(int)
        
        self.htmlInfo_TCP = {}
        self.burstNum_TCP = {}
        self.burstCount_TCP = {}
        self.burstOrder_TCP = {}
        
        self.burstTime_TCP = {}
        
        self.inburstNum_TCP = defaultdict(int)
        self.outburstNum_TCP = defaultdict(int)
        self.packetNumBurst = defaultdict(list)
        self.burstDuration = defaultdict(list)
        
        self.burstPair = []
        for tcp in self.getTcpCons():
            burstCount, htmlSize, packetNumBurst, burstDuration = tcp.getBurstInfo(rvalue, burstPair = burstPair)
            index = tcp.getTimeIndex()
            
            if burstPair: 
                self.burstPair += tcp.burstPair
            
            self.htmlInfo_TCP[index] = htmlSize
            self.burstCount_TCP[index] = burstCount
            self.burstNum_TCP[index] = np.sum(burstCount.values())
            self.burstOrder_TCP[index] = tcp.burstOrder
            
            self.packetNumBurst[index] = packetNumBurst
            self.burstDuration[index] = burstDuration
            
            
            for length, count in burstCount.items(): 
                self.burstCount[length] += count
                if int(length) > 0: 
                    self.inburstNum_TCP[index] += count
                else: 
                    self.outburstNum_TCP[index] += count
        
        ## overall burst bytes
        self.inBurstBytes = []
        self.outBurstBytes = []
        for length, count in self.burstCount.items():
            if length > 0: 
                for i in range(count): 
                    self.inBurstBytes.append(int(length))
            else: 
                for i in range(count): 
                    self.outBurstBytes.append(np.abs(int(length)))  
                    
    def getTraceCount(self, TCPNum):
        BCount = defaultdict(int)
        for time in sorted(self.timeInfoPerTcp)[:TCPNum]:
            for size, count in self.burstCount_TCP[time].items():
                BCount[size] += count
        return BCount
            
    def getBurstOrder(self, BurstNum, TCPNum=None, PacketNum=None, direction=None):
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        burstTime= defaultdict(list)
        if PacketNum:
            burstOrder = self.FburstOrder_TCP
        else:
            burstOrder = self.burstOrder_TCP
            
        for TCPTime in sorted(self.timeInfoPerTcp)[:TCPNum]:
            info = burstOrder[TCPTime]
            for time, burst in info.items():
                if not direction:
                    burstTime[time].append(burst)
                elif direction == Packet.Incoming and burst > 0:
                    burstTime[time].append(burst)
                elif direction == Packet.Outgoing and burst < 0:
                    burstTime[time].append(abs(burst))
        
        orderedBurst = []
        i = 0
        for time in sorted(burstTime.keys()):
            for burst in burstTime[time]:
                if i < BurstNum:
                    orderedBurst.append(burst)
                    i += 1
                else:
                    break
            if i >= BurstNum:
                break
            
        return orderedBurst
    
    def getBurstInfo_N(self, rvalue=1, TCPNum=None, PacketNum=None, burstPair=False):
        self.FburstCount = defaultdict(int)
        self.FhtmlInfo_TCP = {}
        self.FburstNum_TCP = {}
        self.FburstCount_TCP = {}
        self.FburstOrder_TCP = {}
        
        self.FinburstNum_TCP = defaultdict(int)
        self.FoutburstNum_TCP = defaultdict(int)
        self.FpacketNumBurst = defaultdict(list)
        self.FburstDuration = defaultdict(list)
        
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        self.FburstPair = []   
        for tcp in self.getTcpCons()[:TCPNum]:
            burstCount, htmlSize, packetNumBurst, burstDuration = tcp.getBurstInfo(rvalue, burstPair=burstPair, PacketNum=PacketNum)
            index = tcp.getTimeIndex()
            
            if burstPair: 
                self.FburstPair += tcp.burstPair
            
            self.FhtmlInfo_TCP[index] = htmlSize
            self.FburstCount_TCP[index] = burstCount
            self.FburstNum_TCP[index] = np.sum(burstCount.values())
            self.FburstOrder_TCP[index] = tcp.burstOrder
            
            self.FpacketNumBurst[index] = packetNumBurst
            self.FburstDuration[index] = burstDuration
            
            for length, count in burstCount.items(): 
                self.FburstCount[length] += count
                if int(length) > 0: 
                    self.FinburstNum_TCP[index] += count
                else: 
                    self.FoutburstNum_TCP[index] += count
        
        ## overall burst bytes
        self.FinBurstBytes = []
        self.FoutBurstBytes = []
        for length, count in self.FburstCount.items():
            if length > 0: 
                for i in range(count): 
                    self.FinBurstBytes.append(int(length))
            else: 
                for i in range(count): 
                    self.FoutBurstBytes.append(np.abs(int(length)))                                     
        
    def burstSizeNTCP(self, tcpNum, burstNum, direction=None):
        if tcpNum >= len(self.timeInfoPerTcp): 
            return 0
        
        index = self.timeInfoPerTcp[tcpNum]
        if direction:
            burstInfo = {}
            for time, burst in self.burstOrder_TCP[index]:
                if (direction == Packet.incoming and burst > 0) or (direction == Packet.outgoing and burst < 0):
                    burstInfo[time] = burst
        else:
            burstInfo = self.burstOrder_TCP[index]
            
        if burstNum >= len(burstInfo): 
            return 0
        
        tIndex = 0
        for time in sorted(burstInfo):
            if tIndex == burstNum: 
                return burstInfo[time]
            tIndex += 1
        return 0
    
    def getBurstBytes(self, TCPNum=None, PacketNum=None, direction=None):
        bytes = []
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
        
        info = self.FburstOrder_TCP if PacketNum else self.burstOrder_TCP
        for time in sorted(self.timeInfoPerTcp)[:TCPNum]:
            for byte in info[time].values():
                if direction == None:
                    bytes.append(abs(byte))
                elif direction==Packet.Incoming and byte>0:
                    bytes.append(byte)
                elif direction==Packet.Outgoing and byte<0:
                    bytes.append(abs(byte))
        return bytes
    
    def getBurstNum(self, TCPNum=None, PacketNum=None, direction=None):
        burstNum = []
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for time in sorted(self.timeInfoPerTcp)[:TCPNum]:
            if direction==None:
                num = self.outburstNum_TCP[time]+self.inburstNum_TCP[time] if not PacketNum else self.FoutburstNum_TCP[time]+self.FinburstNum_TCP[time]
            elif direction==Packet.Incoming:
                num = self.inburstNum_TCP[time] if not PacketNum else self.FinburstNum_TCP[time]
            else:
                num = self.outburstNum_TCP[time] if not PacketNum else self.FoutburstNum_TCP[time]
            burstNum.append(num)
        return burstNum
        
    def getPacketNumBurst(self, TCPNum=None,PacketNum=None,direction=None):
        packetNum  = []
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        info = self.packetNumBurst if not PacketNum else self.FpacketNumBurst
        for tcpIndex in sorted(self.timeInfoPerTcp)[:TCPNum]:
            for num in info[tcpIndex]:
                if direction == None: 
                    packetNum.append(np.abs(num))
                elif direction == Packet.Incoming and num > 0: 
                    packetNum.append(num)
                elif direction == Packet.Outgoing and num < 0: 
                    packetNum.append(np.abs(num))
        return packetNum
    
    def getNPacketNumBurst(self, tcpId, direction = None):
        packetNum = []
        nums = self.packetNumBurst[self.timeInfoPerTcp[tcpId - 1]] if self.getTcpConsNum() >= tcpId else []
        if direction == None: packetNum = [np.abs(num) for num in nums]
        elif direction == Packet.Incoming: packetNum = [num for num in nums if num > 0]
        elif direction == Packet.Outgoing: packetNum = [np.abs(num) for num in nums if num < 0]
        return packetNum
    
    def getBurstDuration(self, TCPNum=None, PacketNum=None, direction=None):
        burstDuration = []
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        for tcpIndex in sorted(self.timeInfoPerTcp)[:TCPNum]:
            if not PacketNum: 
                durations = self.burstDuration[tcpIndex]
            else:
                durations = self.FburstDuration[tcpIndex]
            
            if direction == None:
                burstDuration += [np.abs(float(duration)) for duration in durations]
            elif direction == Packet.Incoming: 
                burstDuration += [np.abs(float(duration)) for duration in durations if '-' not in duration]
            elif direction == Packet.Outgoing: 
                burstDuration += [np.abs(float(duration)) for duration in durations if '-' in duration]
        return burstDuration
    
    def getNBurstDuration(self, tcpId, direction=None):
        burstDuration = []
        durations = self.burstDuration[self.timeInfoPerTcp[tcpId - 1]] if self.getTcpConsNum() >= tcpId else []
        
        if direction == None:
            burstDuration = [np.abs(float(duration)) for duration in durations]
        elif direction == Packet.Incoming: 
            burstDuration = [float(duration) for duration in durations if '-' not in duration]
        elif direction == Packet.Outgoing: 
            burstDuration = [np.abs(float(duration)) for duration in durations if '-' in duration]
            
        return burstDuration
            
#     def burstNum(self, direction = None):
#         if direction == None: 
#             return (len(self.inBurstBytes) + len(self.outBurstBytes))
#         elif direction == Packet.Incoming: 
#             return len(self.inBurstBytes)
#         else: return len(self.outBurstBytes)
        
    def getBurstNumRatio(self, TCPNum=None, PacketNum=None):
        burstNumRatio = []
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        for time in sorted(self.timeInfoPerTcp)[:TCPNum]:
            if not PacketNum:
                inBurstNum = self.inburstNum_TCP[time]
                outBurstNum = self.outburstNum_TCP[time]
            else:
                inBurstNum = self.FinburstNum_TCP[time]
                outBurstNum = self.FoutburstNum_TCP[time]
            burstNumRatio.append(inBurstNum/(inBurstNum+outBurstNum))
        return burstNumRatio
            
    def burstNumTCP(self, tcpId, direction = None):
        if self.getTcpConsNum() < tcpId: return 0
        
        index = self.timeInfoPerTcp[tcpId - 1]
        num = 0
        for length, count in self.burstCount_TCP[index].items():
            if length > 0 and direction == Packet.Incoming: 
                num += count
            elif length < 0 and direction == Packet.Outgoing: 
                num += count
            elif direction == None: num += count
        return num

     ## same as TCP bytes
    def burstBytesTCP(self, tcpId, direction = None):
        if self.getTcpConsNum() < TcpId: return 0
        index = self.timeInfoPerTcp[TcpId - 1]
        bytes = 0
        for length, count in self.burstCount_TCP(index).items():
            if length > 0 and direction == Packet.Incoming: bytes += (count * abs(size))
            elif length < 0 and direction == Packet.outgoing: bytes += (count * abs(size))
            elif direction == None: bytes += (count * abs(size))
        return bytes
    
    def burstInfoNTCP(self, tcpNum):
        ## burst count of the first N tcp connection
        index = 0
        inBurstBytes = []
        outBurstBytes = []
        burstCountInfo = defaultdict(int)
        inBurstNum = np.zeros(tcpNum)
        outBurstNum = np.zeros(tcpNum)
        inBurstBytesTCP = np.zeros(tcpNum)
        outBurstBytesTCP = np.zeros(tcpNum)
        
        for tcpIndex in sorted(self.timeInfoPerTcp):
            if index >= tcpNum: break
            inBurstNum[index] = self.inburstNum_TCP[tcpIndex]
            outBurstNum[index] = self.outburstNum_TCP[tcpIndex]
            
            info = self.burstCount_TCP[tcpIndex]
            for size, count in info.items():
                burstCountInfo[size] += count
                for i in range(count):
                    if size > 0: inBurstBytes.append(size)
                    else: outBurstBytes .append(size)
            index += 1
            
        inBurstNumRatio = np.zeros(tcpNum)
        for i in range(len(inBurstNum)):
            if inBurstNum[i] + outBurstNum[i] != 0 and inBurstNum[i] != 0:
                inBurstNumRatio[i] = inBurstNum[i]/ (inBurstNum[i] + outBurstNum[i])
                
        return burstCountInfo, [inBurstBytes, outBurstBytes, inBurstNum, outBurstNum, inBurstNumRatio]

    def HtmlSizeofTCP(self, tcpId):
        return self.htmlInfo_TCP[self.timeInfoPerTcp[tcpId - 1]] if self.getTcpConsNum() >= tcpId else 0 
    
    def getHtmlSizeTCP(self, TCPNum=None, PacketNum=None):
        htmlInfo  = []
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        for time in sorted(self.timeInfoPerTcp)[:TCPNum]:
            if PacketNum:
                htmlInfo.append(self.FhtmlInfo_TCP[time])
            else:
                htmlInfo.append(self.htmlInfo_TCP[time])
        return htmlInfo
    
#     def numMarkerofTCP(self, tcpId):
#         return self.burstNum_TCP[self.timeInfoPerTcp[tcpId - 1]] if self.getTcpConsNum() >= tcpId else 0
    
#     def markersInfoNTCP(self, tcpNum):
#         index = 0
#         markersInfo  = []
#         for tcpIndex in sorted(self.timeInfoPerTcp):
#             if index >= tcpNum: break
#             markersInfo.append(self.burstNum_TCP[tcpIndex])
#             index += 1
#         return markersInfo
       
    ################ features associated with tcp connection#################
#     def bytesOfTCP(self, direction, TcpId):
#         if self.getTcpConsNum() < TcpId: return 0
#         index = self.timeInfoPerTcp[TcpId - 1]
#         if direction == Packet.Incoming: return self.inBytesperCon[index] if len(self.inBytesperCon) >= TcpId else 0
#         else: return self.outBytesperCon[index] if len(self.outBytesperCon) >= TcpId else 0
        
#     def bytesInfoNTCP(self, tcpNum):
#         index = 0
#         inBytesTCP = np.zeros(tcpNum)
#         outBytesTCP = np.zeros(tcpNum)
#         inBytesRatioTCP = np.zeros(tcpNum)
#         for tcpIndex in sorted(self.timeInfoPerTcp):
#             if index >= tcpNum: break
#             inBytesTCP[index] = self.inBytesperCon[tcpIndex]
#             outBytesTCP[index] = self.outBytesperCon[tcpIndex]
#             if inBytesTCP[index] + outBytesTCP[index] != 0: 
#                 inBytesRatioTCP[index] = inBytesTCP[index] / (inBytesTCP[index] + outBytesTCP[index])
#             index += 1
#         return [inBytesTCP, outBytesTCP, inBytesRatioTCP]
    
    def getInBytesRatio(self):
        self.inBytesRatio = np.zeros(self.getTcpConsNum())
        i = 0
        for time in sorted(self.timeInfoPerTcp):
            totalBytes = self.inBytesperCon[time] + self.outBytesperCon[time]
            if totalBytes != 0: 
                self.inBytesRatio[i] = self.inBytesperCon[time] / totalBytes
            i+=1
        return self.inBytesRatio
            
    ######## time features in Tcp ###########
    def getInterpacketTimeInfo(self, normalized=False, TCPNum=None, InterNum=None, direction=None):
        if self.getTcpConsNum() == 0: 
            return np.zeros(1)
        
        packetTimeInfo = []
        interNum = 0
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
            
        #### inter-packet time per tcp connection
        for TCP in self.getTcpCons()[:TCPNum]:
            if TCP.getPacketNum() == 1: 
                packetTimeInfo.append([0])
                continue
                
            interTime = TCP.getInterTime(direction=direction,InterNum=InterNum)
            if not normalized or np.max(interTime)==0: 
                packetTimeInfo.append(interTime)
            else: 
                packetTimeInfo.append(interTime/np.max(interTime))
    
        if len(packetTimeInfo) ==0:
            packetTimeInfo.append([0])
        return packetTimeInfo
    
    ## average inter-packet time per interval
    def averageInterpacketTime(self, TCPNum=None,InterNum=20,direction=None,normalized=False):
        if self.getTcpConsNum() == 0: 
            return np.zeros(1)
        
        timeInfoTCP= self.getInterpacketTimeInfo(TCPNum=TCPNum,InterNum=InterNum,direction=direction)
        
        timePerInterval=np.zeros(InterNum)
        
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for time in timeInfoTCP:
            
            for i in range(len(time)): 
                timePerInterval[i] += time[i]
       
        averTime = np.around(np.divide(timePerInterval, TCPNum),3)
        if not normalized or np.max(averTime)==0: 
            return averTime
        return np.around(np.divide(averTime,np.max(averTime)),3)
    
    def averageInterpacketTimePerTCP(self,TCPNum=None,InterNum=None,direction=None,normalized=False):
        if self.getTcpConsNum() == 0: 
            return np.zeros(1)
        
        timeInfoTCP= self.getInterpacketTimeInfo(TCPNum=TCPNum,InterNum=InterNum,direction=direction)
        
        averageTimeTCP = []
        for timeTCP in timeInfoTCP: 
            averageTimeTCP.append(round(np.average(timeTCP),3))
            
        if not normalized or np.max(averageTimeTCP)==0: 
            return averageTimeTCP
       
        return np.round(np.divide(averageTimeTCP,np.max(averageTimeTCP)),3)
    
    def averageInterpacketTimeTCP(self,TCPNum=None,InterNum=None,direction=None):
        if self.getTcpConsNum() == 0: 
            return np.zeros(1)
        
        timeInfoTCP= self.getInterpacketTimeInfo(TCPNum=TCPNum,InterNum=InterNum,direction=direction)
        time = 0
        num = 0
        for timeTCP in timeInfoTCP: 
            time += np.sum(timeTCP)
            num += len(timeTCP)
        return round(time/num, 3)
    
    def getFLPacketConcentration(self, N=30, TCPNum=None, PacketNum=None, First=True, Last=True):
        fInPacketCons = 0
        fOutPacketCons = 0
        lInPacketCons = 0
        lOutPacketCons = 0
        
        packets = self.getPackets(TCPNum=TCPNum, PacketNum=PacketNum)
        for packet in packets[:30]:
            if packet > 0:
                fInPacketCons += 1
            else:
                fOutPacketCons += 1
        
        for packet in packets[-30:]:
            if packet > 0:
                lInPacketCons += 1
            else:
                lOutPacketCons += 1
                
        return [fInPacketCons, fOutPacketCons, lInPacketCons, lOutPacketCons]
    
    def getPacketConcentration(self, binSize=20, TCPNum=None, PacketNum=None):
        count = 0
        conOutPackets = [] ## concentration of outgoing packets
        packets = self.getPackets(TCPNum=TCPNum,PacketNum=PacketNum)[:2000]
        length = len(packets)
        for i in range(length):
            if i != 0 and i%binSize==0:
                conOutPackets.append(count)
                count = 0
                if packets[i] < 0:
                    count += 1
            else: 
                if packets[i] < 0:
                    count += 1
                
        conOutPackets.append(count)
        for i in range(int(math.ceil(length/binSize)), int(2000.0/binSize)):
            conOutPackets.append(0)  
        return conOutPackets
    
    def getTransposition(self, TCPNum=None, PacketNum=None, In=True, Out=True):
        packets = self.getPackets(TCPNum=TCPNum,PacketNum=PacketNum)
        if Out:
            outPacketLoc = []
            outPreLoc = []
            count = 0
            prevloc = 0
            for i in range(len(packets)):
                if packets[i] < 0:
                    count += 1
                    outPacketLoc.append(i)
                    outPreLoc.append(i-prevloc)
                    prevloc = i
                if count == 300: 
                    break

            for i in range(min(count,300), 300):
                outPacketLoc.append(0)
                outPreLoc.append(0)
         
        if In:
            inPacketLoc = []
            inPreLoc = []
            count = 0
            prevloc = 0
            for i in range(len(packets)):
                if packets[i] > 0:
                    count += 1
                    inPacketLoc.append(i)
                    inPreLoc.append(i-prevloc)
                    prevloc = i
                if count == 300:
                    break
            for i in range(min(count,300), 300):
                inPacketLoc.append(0)
                inPreLoc.append(0)
        if In and Out:
            return [outPacketLoc, outPreLoc, inPacketLoc, inPreLoc]
        if In:
            return [inPacketLoc, inPreLoc]
        if Out:
            return [outPacketLoc, outPreLoc]
          
            
    ## average inter-packet time per TCP
            
    def getDuration(self,TCPNum=None,PacketNum=None, direction=None):
        if self.getTcpConsNum() == 0: 
            return 0
        
        if not TCPNum and not PacketNum and not direction:
            sTime, eTime = self.getTraceTime()
            return round(float((eTime - sTime)), 3)
        
        if not TCPNum:
            TCPNum = self.getTcpConsNum()
        
        sTime = np.inf
        eTime = 0
        if not PacketNum and not direction:
            timeInfo = self.timeInfoPerTcp[:TCPNum]
            for time in timeInfo:
                tmp = time.split(':')
                sTime = min(sTime, float(tmp[0]))
                eTime = max(eTime, float(tmp[1]))
        else:
            for TCP in self.getTcpCons()[:TCPNum]:
                packets = TCP.getPackets(direction=direction)
                if PacketNum:
                    packets = packets[:PacketNum]
                    
                if len(packets) == 0:
                    continue
                sTime = min(packets[0].getTime(), sTime)
                eTime = max(packets[-1].getTime(), eTime)
          
        time = eTime-sTime
        return np.round(time, 3) if time != -np.inf else 0
                
    ##### interTime per Tcp in a trace ########
    def startTimeperTcp(self, normalized = False, rounded = True):
        self.sTime = []
        if len(self.timeInfoPerTcp) == 0: 
            return self.sTime
        
        startTime = float(self.timeInfoPerTcp[0].split(':')[0])
        for info in self.timeInfoPerTcp[1:]:
            self.sTime.append(float((float(info.split(':')[0]) - startTime)))
        
        if normalized: 
            if len(self.timeInfoPerTcp) != 1 and self.sTime[0] != 0: 
                sTime_ratio = np.around(np.divide(self.sTime, self.sTime[0]),3)
            else: sTime_ratio = self.sTime
            if rounded: sTime_ratio = [Utility.roundToPowerofX(time, 2) for time in sTime_ratio]
            return sTime_ratio
        return self.sTime
    
    def endTimeperTcp(self, normalized=False, rounded = True):
        self.eTime = []
        if len(self.timeInfoPerTcp) == 0: return self.eTime
        startTime = float(self.timeInfoPerTcp[0].split(':')[0])
        for info in self.timeInfoPerTcp:
            self.eTime.append(float((float(info.split(':')[1]) - startTime)))
            
        if normalized:
            if len(self.timeInfoPerTcp) != 1 and self.eTime[0] != 0: 
                eTime_ratio = np.around(np.divide(self.eTime, self.eTime[0]), 3)
            else: 
                eTime_ratio = self.eTime
            if rounded: 
                eTime_ratio = [Utility.roundToPowerofX(time,2) for time in eTime_ratio]
            return eTime_ratio
        return self.eTime
    
    def durTimeperTcp(self, normalized=False, rounded=True):
        self.dTime = []
        if len(self.timeInfoPerTcp) == 0: 
            return self.dTime
        
        for info in self.timeInfoPerTcp:
            self.dTime.append(round(float(info.split(':')[1]) - float(info.split(':')[0]),3))
        
        if normalized:
            if len(self.timeInfoPerTcp) != 1 and self.dTime[0] != 0: 
                dTime_ratio = np.around(np.divide(self.dTime, self.dTime[0]), 3)
            else: 
                dTime_ratio = self.dTime
            if rounded: 
                dTime_ratio = [Utility.roundToPowerofX(time, 2) for time in dTime_ratio]
            return dTime_ratio
        return self.dTime
            
    ########### features associated with port num ##############
    def getPortCount(self, TCPNum=None):
        portCount = defaultdict(int)
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for TCP in self.getTcpCons()[:TCPNum]:
            TCP.parseSrcDstPortInfo()
            portCount[TCP.serverPort] += 1
            
        return portCount
    
    def getPortBytes(self,TCPNum=None,PacketNum=None):
        portBytes=defaultdict(list)
        inPortBytes=defaultdict(list)
        outPortBytes=defaultdict(list)
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
        
        for TCP in self.getTcpCons()[:TCPNum]:
            TCP.parseSrcDstPortInfo()
            tolBytes = TCP.totalBytes(PacketNum=PacketNum)
            inBytes = TCP.totalBytes(PacketNum=PacketNum, direction=Packet.Incoming)
            outBytes = TCP.totalBytes(PacketNum=PacketNum, direction=Packet.Outgoing)
            
            portBytes[TCP.serverPort].append(tolBytes)
            inPortBytes[TCP.serverPort].append(inBytes)
            outPortBytes[TCP.serverPort].append(outBytes)
        
        return portBytes, inPortBytes, outPortBytes
            
    def getPortId(self):
        return self.portcount.keys() if len(self.portcount) > 0 else 0
    
    ########### server address and server port #############
    def serverAddrCount(self, threeField=True,TCPNum=None):
        addrCount = defaultdict(int)
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for tcp in self.getTcpCons()[:TCPNum]:
            tcp.parseSrcDstPortInfo()
            if threeField:
                temp = tcp.serverAddr.split('.')
                serverAddr = '.'.join([temp[0], temp[1], temp[2]])
                addrCount[serverAddr] += 1
            else: 
                addrCount[tcp.serverAddr] += 1
        return addrCount
    
    def getServerAddrBytes(self,TCPNum=None,PacketNum=None,threeField=False):
        self.addrBytesTCP = defaultdict(list)
        addrBytes = defaultdict(list)
        inAddrBytes = defaultdict(list)
        outAddrBytes = defaultdict(list)
        
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for TCP in self.getTcpCons()[:TCPNum]:
            if not TCP.serverAddr:
                TCP.parseSrcDstPortInfo()
                
            if threeField: 
                tmp = TCP.serverAddr.split('.')
                serverAddr = '.'.join(tmp[:3])
            else: 
                serverAddr = TCP.serverAddr
            
            addrBytesTCP = defaultdict(list)
            
            tolBytes = TCP.totalBytes(PacketNum=PacketNum)
            inBytes = TCP.totalBytes(direction=Packet.Incoming,PacketNum=PacketNum)
            outBytes = TCP.totalBytes(PacketNum=PacketNum, direction=Packet.Outgoing)
            
            addrBytes[serverAddr].append(tolBytes)
            inAddrBytes[serverAddr].append(inBytes)
            outAddrBytes[serverAddr].append(outBytes)
            
        return addrBytes, inAddrBytes, outAddrBytes

    def addrPortCount(self, first_three_fields = True):
        self.addrPortCount = defaultdict(int)
        for tcp in self.getTcpCons():
            tcp.parseSrcDstPortInfo()
            if first_three_fields: 
                temp = tcp.serverAddr.split('.')
                serverAddr = '.'.join([temp[0], temp[1], temp[2]])
            else: serverAddr = tcp.serverAddr
            index = serverAddr + ':' + str(tcp.serverPort)
            self.addrPortCount[index] += 1
        return self.addrPortCount
    
    def addrPortBytes(self):
        self.addrPortBytesTCP = defaultdict(list)
        sel.addrPortBytes = defaultdict(float)
        for tcp in self.getTcpCons():
            addrPortBytesTCP = defaultdict(float)
            tcp.parseSrcDstPortInfo()
            temp = tcp.serverAddr.split('.')
            serverAddr = '.'.join([temp[0], temp[1], temp[2]])
            index = serverAddr + ':' + str(tcp.serverPort)
            tcpIndex = tcp.getTimeIndex()
            inBytes = tcp.totalBytes(Packet.Incoming)

            if inBytes > 0: 
                addrPortBytesTCP[index].append(inBytes)
                self.addrPortBytesTCP[index].append(inBytes)
                
            outBytes = tcp.totalBytes(Packet.Outgoing)* (-1)
            if outBytes > 0: 
                addrPortBytesTCP[index].append(outBytes)
                self.addrPortBytesTCP[index].append(outBytes)
                
            self.addrPortBytesTCP[tcpIndex] = addrPortBytesTCP
            
    def getHostnameCount(self, TCPNum=None):
        hostCount = defaultdict(int)
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for TCP in self.getTcpCons()[:TCPNum]:
            if not TCP.serverAddr:
                TCP.parseSrcDstPortInfo()
            if not TCP.hostname:
                hostname = TCP.getHostname()
            if TCP.hostname != 'NA' and TCP.hostname:
                hostCount[TCP.hostname] += 1
            
        return hostCount
        
    def getHostnameBytes(self,TCPNum=None,PacketNum=None):
        addrBytes = defaultdict(list)
        inAddrBytes = defaultdict(list)
        outAddrBytes = defaultdict(list)
        
        if not TCPNum:
            TCPNum=self.getTcpConsNum()
            
        for TCP in self.getTcpCons()[:TCPNum]:
            if not TCP.serverAddr:
                TCP.parseSrcDstPortInfo()
                
            if not TCP.hostname:
                hostname = TCP.getHostname()
                
            if TCP.hostname and TCP.hostname != 'NA':
                tolBytes = TCP.totalBytes(PacketNum=PacketNum)
                inBytes = TCP.totalBytes(direction=Packet.Incoming,PacketNum=PacketNum)
                outBytes = TCP.totalBytes(PacketNum=PacketNum, direction=Packet.Outgoing)

                addrBytes[TCP.hostname].append(tolBytes)
                inAddrBytes[TCP.hostname].append(inBytes)
                outAddrBytes[TCP.hostname].append(outBytes)
            
        return addrBytes, inAddrBytes, outAddrBytes