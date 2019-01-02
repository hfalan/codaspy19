from Packet import Packet
import numpy as np
from collections import defaultdict
import Utility, Config
import subprocess as sub

class TCPConnection(object):
    def __init__(self, tcpId, webId, hostip = None):
        self._tcpId = tcpId
        self._webId = webId
        self._packets = []
        self._hostip = hostip
        
        ## incoming and outgoing packets number and total transmitted bytes
        self.inpackets = []
        self.outpackets = []
        
        ## tcp duration
        self._startTime = np.inf
        self._endTime = 0
        
        self.PSHACKNum = 0
        
        self.serverAddr = None
        self.serverPort = None
        self.hostname = None
        
        self.packetOrdering = []
        self.ordered = False
        if hostip != None: 
            self.parseSrcDstPortInfo()
        else: self._hostip == None
    
    def getHostIp(self):
        return self._hostip
    
    def setHostIp(self, hostip):
        self._hostip = hostip
        self.parseSrcDstPortInfo()
    
    def addPacket(self, packet):
        length = packet.getLength()  
        self._packets.append(packet)
        
        length = packet.getLength()
        if packet.getDirection() == Packet.Incoming: self.inpackets.append(length)
        else: self.outpackets.append(length)
         
        time = packet.getTime()
        if time < self._startTime: 
            self._startTime = time
        if time > self._endTime: 
            self._endTime = time
            
        if packet.getFlag() == Packet.PSH_ACK and packet.getLength() == Packet.Packet_Header: 
            self.PSHACKNum += 1
            
        #self._packets.sort(key=lambda x: x.getTime())
            
    def getTcpId(self):
        return self._tcpId
    
    def setTcpId(self, tcpId):
        self._tcpId = tcpId
    
    def getWebId(self):
        return self._webId
    
    def getTransTime(self):
        return self._startTime, self._endTime
    
    def getPacketNum(self, direction=None):
        if direction == Packet.Incoming: 
            return len(self.inpackets)
        elif direction == Packet.Outgoing: 
            return len(self.outpackets)
        else: return (len(self.inpackets) + len(self.outpackets))
        
    def totalBytes(self, direction=None, PacketNum=None):
        if not PacketNum:
            PacketNum=self.getPacketNum()
        info = self.getPacketOrder()[:PacketNum]
        
        if direction == Packet.Incoming: 
            return np.sum([abs(p) for p in info if p > 0])
        elif direction == Packet.Outgoing: 
            return np.sum([abs(p) for p in info if p < 0])
        return np.sum([abs(p) for p in info])
    
    def maxBytes(self, direction):
        if direction == Packet.Incoming: return np.max(self.inpackets)
        else: return np.max(self.outpackets)
        
    def minBytes(self, direction):
        if direction == Packet.Incoming: return np.min(self.inpackets)
        else: return np.min(self.outpackets)
        
    def meanBytes(self, direction):
        if direction == Packet.Incoming: return np.average(self.inpackets)
        else: return np.average(self.outpackets)
    
    def medianBytes(self,direction):
        if direction == Packet.Incoming: return np.median(sorted(self.inpackets))
        else: return np.median(sorted(self.outpackets))
        
    def percentileBytes(self, percentage, direction):
        if direction == Packet.Incoming: return np.percentile(sorted(self.inpackets), percentage)
        else: return np.percentile(sorted(self.outpackets), percentage)
        
    def getTimeIndex(self):
#         print self._startTime, self._endTime, self._tcpId
        timeIndex = ":".join([format(self._startTime, '.3f'),format(self._endTime, '.3f'), str(self._tcpId)])
        return timeIndex
    
    def getPackets(self, direction=None):
        packets = []
        for packet in self._packets:
            if packet.getDirection() == direction or not direction: 
                packets.append(packet)
        return packets

    ## can consider only first N packets
    def getBurstInfo(self, rvalue=1, includeTimeInterval=True, burstPair=False, PacketNum=None):
        self._burstCount = defaultdict(int)
        self._htmlSize = 0
        burstLength = 0
        htmlFlag = True
        packetNum = 1
        self.packetNumBurst = []
        self.burstOrder = {}
    
        self.burstPair = []
        startTime = 0
        cacheTime = 0 ## used when we do not consider the transmission time
        self.burstDuration = []
        
        if not PacketNum:
            PacketNum = self.getPacketNum()
            
        for packet in self._packets[:PacketNum]:
            length = packet.getLength()
            if packet.getDirection() == Packet.Outgoing: 
                length = length * (-1)
            if burstLength == 0: 
                burstLength += length
                startTime = packet.getTime()
                cacheTime = startTime
                continue
            
            if burstLength * length < 0:
                if burstLength > 10**7: 
                    burstLength = 10**7
                if burstLength <  -10**7:
                    burstLength = -10**7
                burstLength = Utility.roundToX(burstLength, rvalue)
                
                self._burstCount[burstLength] += 1
                self.burstOrder[startTime] = burstLength
                
                if htmlFlag and burstLength > 0:
                    self._htmlSize = burstLength
                    htmlFlag = False
                
                ## ms
                if includeTimeInterval:
                    duration = str(round((packet.getTime() - startTime),3))
#                     if packet.getTime()-startTime < 0:
#                         print packet.getTime()-startTime, packet.getTime(), startTime
                else: 
                    duration = str(round(cacheTime - startTime),3)
                    
                    
                if burstLength < 0: 
                    packetNum = packetNum * (-1)
                    duration = '-' + duration
                    
                if burstPair:
                    if burstLength < 0: 
                        s = np.abs(burstLength)
                    elif burstLength > 0: 
                        self.burstPair.append((s, burstLength))
                self.burstDuration.append(duration)
                self.packetNumBurst.append(packetNum)
                packetNum = 1
                
                startTime = packet.getTime()
                cacheTime = startTime
                burstLength = length
            else: 
                burstLength += length
                packetNum += 1
                cacheTime = packet.getTime()
                
        if htmlFlag and burstLength > 0: 
            self._htmlSize = burstLength
        
        
        burstLength = Utility.roundToX(burstLength, rvalue)
        self._burstCount[burstLength] += 1
        self.burstOrder[startTime] = burstLength
        if burstPair:
            if burstLength < 0: s = np.abs(burstLength) 
            elif burstLength > 0: self.burstPair.append((s, burstLength))
        
        duration = str(packet.getTime() - startTime)
        if burstLength < 0: 
            packetNum = packetNum * (-1)
            duration = '-' + duration
            
        self.packetNumBurst.append(packetNum)
        self.burstDuration.append(duration) 
        return self._burstCount, self._htmlSize, self.packetNumBurst, self.burstDuration
    
    ## get interpacket time with a tcp
    def getInterTime(self, direction=None, InterNum=None):
        if self.getPacketNum(direction=direction) <= 1:
            return [0]
        
        interTime = []
        timeCursor = 0
        index = 0
        for packet in self._packets:
            if not direction or direction == packet.getDirection():
                time = packet.getTime()
                if timeCursor == 0: 
                    timeCursor = time
                    continue
                interTime.append(round((time-timeCursor),3))
                timeCursor = time
                index +=1
                if InterNum and index>=InterNum:
                    break
                    
        if len(interTime)==0:
            interTime.append(0)
#         if InterNum:
#             for i in range(min(len(interTime), InterNum), InterNum):
#                 interTime.append(0)
        return interTime
    
    def setTimeStamp(self, timeStamp):
        self._startTime = timeStamp  
        self._endTime = timeStamp
        
    def getPacketOrder(self, PacketNum=None):
        if not self.ordered:
            for packet in self._packets[:PacketNum]:
                length = packet.getLength()
                self.packetOrdering.append(length*(-1) if packet.getDirection() == Packet.Outgoing else length)
            self.ordered=True
            
        if not PacketNum: 
            PacketNum = self.getPacketNum()
        return self.packetOrdering[:PacketNum]
    
    ######## for hasan datasets only ##########
    def parseSrcDstPortInfo(self):
        addr1, port1 = self._tcpId.split('-')[0].split(':')
        addr2, port2 = self._tcpId.split('-')[1].split(':')
        
        if addr1 == self._hostip: 
            self.clientPort = int(port1)
            self.clientAddr = addr1
            self.serverPort = int(port2)
            self.serverAddr = addr2
        elif addr2 == self._hostip:
            self.clientPort = int(port2)
            self.clientAddr = addr2
            self.serverPort = int(port1)
            self.serverAddr = addr1
        #else: 
            #print "Error: No match IP"
            #print  self._tcpId, self._hostip
            
    def getHostname(self):
        if self.serverAddr not in Config.hostname.keys():
            return 'NA'
        self.hostname = Config.hostname[self.serverAddr]
        return self.hostname
            
# #         cmd = "host %s"%self.serverAddr
# #         process = sub.Popen(cmd, shell=True, stdout=sub.PIPE,stderr=sub.PIPE)
# #         output, err = process.communicate()
# #         if '(NXDOMAIN)' in output: 
# #             return 'NA'

# #         index = output.strip('\n').split(' ')[-1]
# #         if '.' not in index:
# #             return 'NA'

# #         self.hostname = '.'.join([i for i in index.split('.')[-3:-1]])
#         return self.hostname
            