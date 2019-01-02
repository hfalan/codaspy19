class Packet(object):
    
    Incoming = 1
    Outgoing = 2
    
    ## size of packet header
    Packet_Header = 52
    
    SYN = '0x0002'
    ACK = '0x0010'
    FIN_ACK = '0x0011'
    SYN_ACK = '0x0012'
    PSH_ACK = '0x0018'
    
    ## [u'0x0018', u'0x0010']
    
    MTU = 1500
    
    def __init__ (self, time, length, direction, flag = None):
        self._time = time
        self._length = length
        self._direction = direction
        self._flag = flag
#         self.checkSignalPacket()
    
    def getTime(self):
        return self._time
    
    def getLength(self):
        return self._length
    
    def getDirection(self):
        return self._direction
    
    def getFlag(self):
        return self._flag
    
    def setLength(self, length):
        self._length = length
        
    def setTime(self, time):
        self._time = time
        
#     def checkSignalPacket(self):
#         if self._flag == SYN or self._flag == FIN_ACK or self._flag == SYN_ACK: self._ack = True
#         elif self._flag == ACK and self._length == Packet_Header: self._ack = True
#         else: self._ack = False
            
#     def isSignalPacket(self):
#         return self._ack