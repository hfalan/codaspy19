from __future__ import division
import Utility
import numpy as np
from collections import defaultdict
from Packet import Packet
from collections import Counter


portIds = [80, 443]

## top 20 common server addresses
# SERVER_ADDRESS = [u'31.13.69.203', u'31.13.71.7', u'216.58.217.162', u'216.58.217.66', u'216.58.218.226', u'31.13.69.228', u'216.58.217.98', u'31.13.71.36', u'216.58.217.130', u'204.85.32.27', u'173.241.242.143', u'169.47.30.64', u'199.96.57.6', u'172.217.1.194', u'151.101.32.207', u'172.217.1.2', u'204.85.32.25', u'216.58.195.130', u'172.217.2.194', u'192.82.242.21']

#SERVER_ADDRESS = [u'216.58.217', u'204.85.30', u'204.85.32', u'31.13.69', u'31.13.71', u'216.58.218', u'172.217.1', u'54.192.19', u'151.101.32', u'52.85.142', u'68.67.178', u'8.43.72', u'216.58.195', u'172.217.2', u'74.119.118', u'199.16.156', u'173.241.242', u'72.21.91', u'66.150.48', u'199.96.57']

#HOST_NAMES = [u'1e100.net.', 'amazonaws.com.', 'akamaitechnologies.com.', 'cloudfront.net.', 'fbcdn.net.', 'facebook.com.', 'sl-reverse.com.', 'adnexus.net.', 'yahoo.com.', 'quantserve.com', 'openx.org', 'googleusercontent.com.', 'aol.com.', 'nr-data.net.', 'turn.com.', 'yandex.ru.', 'hwcdn.net.', 'btrll.com.', 'a-msedge.net.', 'omtrdc.net.']

## Packet-level information

    ## 1. packet size count
def getPacketSizeCount(features, trace, rvalue, TCPNum=None,PacketNum=None,Count=True, Unique=True,Overall=True, firstN=True):
    if Overall:
        packetCount = trace.getPacketCount(rvalue=rvalue)
        for size, pcount in packetCount.items(): 
            if Count: 
                features[u'1--PC' + str(size)] = pcount 
            if Unique: 
                features[u'2--UP' + str(size)] = 1
    if firstN:
        packetCount = trace.getPacketCount(rvalue=rvalue,TCPNum=TCPNum,PacketNum=PacketNum)
        for size, pcount in packetCount.items(): 
            if Count: 
                features[u'1--FPC' + str(size)] = pcount 
            if Unique: 
                features[u'2--FUP' + str(size)] = 1
        
## get information about number of packets
def getPacketNum(features, trace, TCPNum=None, PacketNum=None,Tol=True,In=True,Out=True,Ratio=True,Overall=True,firstN=True):
    if Overall:
        packetNum, inPacketNum, outPacketNum, inPacketNumRatio = trace.getPacketNum()
        if Tol:
            results = Utility.getStatisticValue(packetNum)
            for label, result in results.items(): 
                features[u'3--' + label + 'PN'] = result

        if In:
            results = Utility.getStatisticValue(inPacketNum)
            for label, result in results.items(): 
                features[u'4--' + label + 'iPN'] = result 

        if Out:
            results = Utility.getStatisticValue(outPacketNum)
            for label, result in results.items():
                features[u'5--' + label + 'oPN'] = result

        if Ratio:
            totalPacketNum = np.sum(packetNum)
            inPacketNum = np.sum(inPacketNum)

            if totalPacketNum != 0:
                features[u'6--riPN'] = round(inPacketNum/totalPacketNum, 3)

            results = Utility.getStatisticValue(inPacketNumRatio)
            for label, result in results.items():
                features[u'6--' + label + 'riPN'] = round(result, 3)
    
    if firstN:
        packetNum, inPacketNum, outPacketNum, inPacketNumRatio = trace.getPacketNum(TCPNum=TCPNum,PacketNum=PacketNum)
        if Tol:
            results = Utility.getStatisticValue(packetNum)
            for label, result in results.items(): 
                features[u'3--F'+label+ 'PN'] = result

        if In:
            results = Utility.getStatisticValue(inPacketNum)
            for label, result in results.items(): 
                features[u'4--F' + label + 'iPN'] = result 

        if Out:
            results = Utility.getStatisticValue(outPacketNum)
            for label, result in results.items():
                features[u'5--F' + label + 'oPN'] = result

        if Ratio:
            totalPacketNum = np.sum(packetNum)
            inPacketNum = np.sum(inPacketNum)

            if totalPacketNum != 0:
                features[u'6--FriPN'] = round(inPacketNum/totalPacketNum, 3)

            results = Utility.getStatisticValue(inPacketNumRatio)
            for label, result in results.items():
                features[u'6--F' + label + 'riPN'] = round(result, 3)
        

    ## number of packets per ms
def getPacketFrequency(features,trace,TCPNum=None,PacketNum=None,Tol=True,In=True,Out=True,Overall=True,firstN=True):
    if Overall:
        packetNum, inPacketNum, outPacketNum, inPacketNumRatio = trace.getPacketNum()
        if Tol:
            time = trace.getDuration()
            if time != 0:
                features[u'7--PF'] = np.round(np.sum(packetNum)/time, 3)
        if In:
            time = trace.getDuration(direction=Packet.Incoming)
            if time != 0:
                features[u'8--iPF'] = np.round(np.sum(inPacketNum)/time, 3)
        if Out:
            time = trace.getDuration(direction=Packet.Outgoing)
            if time != 0:
                features[u'9--oPF'] = np.round(np.sum(outPacketNum)/time, 3)
    if firstN:
        packetNum, inPacketNum, outPacketNum, inPacketNumRatio = trace.getPacketNum(TCPNum=TCPNum,PacketNum=PacketNum)
        if Tol:
            time = trace.getDuration(TCPNum=TCPNum,PacketNum=PacketNum)
            if time != 0:
                features[u'7--FPF'] = np.round(np.sum(packetNum)/time, 3)
        if In:
            time = trace.getDuration(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Incoming)
            if time != 0:
                features[u'8--FiPF'] = np.round(np.sum(inPacketNum)/time, 3)
        if Out:
            time = trace.getDuration(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Outgoing)
            if time != 0:
                features[u'9--FoPF'] = np.round(np.sum(outPacketNum)/time, 3)
    
    ## accumulated packet size of first 100
def getCumulatedPacketSize(features, trace, TCPNum=None,PacketNum=None,Overall=True, firstN=True, direction=True, nonDirection=True):
    if Overall:
        packets = trace.getPackets()[:100]
        cum = 0
        cum_d = 0
        index = 0
        for packet in packets:
            cum += abs(packet)
            cum_d += packet
            if nonDirection:
                features[u'10--CP' + str(index)] = cum
            if direction:
                features[u'11--dCP' + str(index)] = cum_d
            index += 1
            
    if firstN:
        packets = trace.getPackets(TCPNum=TCPNum, PacketNum=PacketNum)[:100]
        cum = 0
        cum_d = 0
        index = 0
        for packet in packets:
            cum += abs(packet)
            cum_d += packet
            if nonDirection:
                features[u'10--FCP' + str(index)] = cum
            if direction:
                features[u'11--FdCP' + str(index)] = cum_d
            index += 1
    
## concentration of outgoing packets in every 20 packets
## Alter stands for the alternative concentration features proposed in k-fingerprinting
def getOutConcentration(features, trace, binSize=20, TCPNum=None,PacketNum=None,Overall=True, firstN=True, Alter=True, Con=True):
    if Overall:
        conOutPackets = trace.getPacketConcentration(binSize=binSize)
        if Con:
            for i in range(len(conOutPackets)):
                if conOutPackets[i] != 0:
                    features[u'12--'+str(i)+'oCP'] = conOutPackets[i]

            results = Utility.getStatisticValue(conOutPackets)
            for label, result in results.items():
                features[u'12--'+label + 'oCP'] = result
                
        if Alter:
            alterCon = []
            num=20
            sbin = int(len(conOutPackets)/num)
            for con in range(num):
                alterCon.append(np.sum(conOutPackets[con*sbin:(con+1)*sbin]))
                
            for i in range(len(alterCon)):
                if alterCon[i] != 0:
                    features[u'13--AC'+str(i)] = alterCon[i]
                    
            results = Utility.getStatisticValue(alterCon, Tol=False)
            for label, result in results.items():
                features[u'13--'+label + 'AC'] = result
            
    if firstN:
        conOutPackets = trace.getPacketConcentration(binSize=binSize,TCPNum=TCPNum,PacketNum=PacketNum)
        if Con:
            for i in range(len(conOutPackets)):
                if conOutPackets[i] != 0:
                    features[u'12--F'+str(TCPNum)+str(i)+'oCP'] = conOutPackets[i]

            results = Utility.getStatisticValue(conOutPackets)
            for label, result in results.items():
                features[u'12--F'+str(TCPNum)+label + 'oCP'] = result
                
        if Alter:
            alterCon = []
            num=20
            sbin = int(len(conOutPackets)/num)
            for con in range(num):
                alterCon.append(np.sum(conOutPackets[con*sbin:(con+1)*sbin]))
                
            for i in range(len(alterCon)):
                if alterCon[i] != 0:
                    features[u'13--FAC'+str(i)] = alterCon[i]
                    
            results = Utility.getStatisticValue(alterCon, Tol=False)
            for label, result in results.items():
                features[u'13--F'+label + 'AC'] = result
            
            
def getFLConcentration(features, trace, N=30, PacketNum=None, TCPNum=None, Overall=True, firstN=True):
    if Overall:
        fIn, fOut, lIn, lOut = trace.getFLPacketConcentration(N=N)
        features[u'14--fiCP'] = fIn
        features[u'15--foCP'] = fOut
        features[u'16--liCP'] = lIn
        features[u'17--loCP'] = lOut
        
    if firstN:
        fIn, fOut, lIn, lOut = trace.getFLPacketConcentration(N=N, PacketNum=PacketNum, TCPNum=TCPNum)
        features[u'14--FfiCP'] = fIn
        features[u'15--FfoCP'] = fOut
        features[u'16--FliCP'] = lIn
        features[u'17--FloCP'] = lOut
        
    ## number of packets each second
def getPacketPerSecond(features, trace, TCPNum=None, PacketNum=None,binSize=1000, In=True, Out=True, Tol=True, Overall=True, firstN=True, Alter=True, All=True):
    if Overall:
        nums, innums, outnums = trace.getPacketNumPerSec(binSize=binSize)
        if Tol:
            if All:
                for i in range(len(nums)):
                    if nums[i] != 0:
                        features[u'18--PFS'+str(i)] = nums[i]

                results = Utility.getStatisticValue(nums, Tol=False)
                for label, result in results.items():
                    features[u'18--PFS'+label] = round(result,3)
                
            if Alter:
                alterCon = []
                num=20
                sbin = int(len(nums)/num)
                for con in range(num):
                    alterCon.append(np.sum(nums[con*sbin:(con+1)*sbin]))
                
                for i in range(len(alterCon)):
                    if alterCon[i] != 0:
                        features[u'21--APS'+str(i)] = alterCon[i]
                        
                results = Utility.getStatisticValue(alterCon)
                for label, result in results.items():
                    features[u'21--APS'+str(label)]=result
                
        if In:
            if All:
                for i in range(len(innums)):
                    if innums[i] != 0:
                        features[u'19--iPFS'+str(i)] = innums[i]

                results = Utility.getStatisticValue(innums, Tol=False)
                for label, result in results.items():
                    features[u'19--iPFS'+label] = round(result,3)
                
            if Alter:
                alterCon = []
                num=20
                sbin = int(len(nums)/num)
                for con in range(num):
                    alterCon.append(np.sum(innums[con*sbin:(con+1)*sbin]))
                    
                for i in range(len(alterCon)):
                    if alterCon[i] != 0:
                        features[u'22--AiPS'+str(i)] = alterCon[i]

                results = Utility.getStatisticValue(alterCon)
                for label, result in results.items():
                    features[u'22--AiPS'+str(label)]=result
                
        if Out:
            if All:
                for i in range(len(outnums)):
                    if outnums[i] != 0:
                        features[u'20--oPFS'+str(i)] = outnums[i]

                results = Utility.getStatisticValue(outnums, Tol=False)
                for label, result in results.items():
                    features[u'20--oPFS'+label] = round(result,3)
                
            if Alter:
                alterCon = []
                num=20
                sbin = int(len(nums)/num)
                for con in range(num):
                    alterCon.append(np.sum(outnums[con*sbin:(con+1)*sbin]))
                    
                for i in range(len(alterCon)):
                    if alterCon[i] != 0:
                        features[u'23--AoPS'+str(i)] = alterCon[i]

                results = Utility.getStatisticValue(alterCon)
                for label, result in results.items():
                    features[u'23--AoPS'+str(label)]=result
            
    if firstN:
        nums, innums, outnums = trace.getPacketNumPerSec(binSize=binSize,TCPNum=TCPNum,PacketNum=PacketNum)
        if Tol:
            if All:
                for i in range(len(nums)):
                    if nums[i] != 0:
                        features[u'18--F'+str(TCPNum)+'PFS'+str(i)] = nums[i]

                results = Utility.getStatisticValue(nums, Tol=False)
                for label, result in results.items():
                    features[u'18--F'+str(TCPNum)+'PFS'+label] = round(result,3)
                
            if Alter:
                alterCon = []
                num=20
                sbin = int(len(nums)/num)
                for con in range(num):
                    alterCon.append(np.sum(nums[con*sbin:(con+1)*sbin]))

                for i in range(len(alterCon)):
                    if alterCon[i] != 0:
                        features[u'21--FAPS'+str(i)] = alterCon[i]
                        
                results = Utility.getStatisticValue(alterCon)
                for label, result in results.items():
                    features[u'21--FAPS'+str(label)]=result    
                
        if In:
            if All:
                for i in range(len(innums)):
                    if innums[i] != 0:
                        features[u'19--F'+str(TCPNum)+'iPFS'+str(i)] = innums[i]

                results = Utility.getStatisticValue(innums, Tol=False)
                for label, result in results.items():
                    features[u'19--F'+str(TCPNum)+'iPFS'+label] = round(result,3)
                
            if Alter:
                alterCon = []
                num=20
                sbin = int(len(nums)/num)
                for con in range(num):
                    alterCon.append(np.sum(innums[con*sbin:(con+1)*sbin]))
                
                for i in range(len(alterCon)):
                    if alterCon[i] != 0:
                        features[u'22--FiAPS'+str(i)] = alterCon[i]

                results = Utility.getStatisticValue(alterCon)
                for label, result in results.items():
                    features[u'22--FiAPS'+str(label)]=result
                
        if Out:
            if All:
                for i in range(len(outnums)):
                    if outnums[i] != 0:
                        features[u'20--F'+str(TCPNum)+'oPFS'+str(i)] = outnums[i]

                results = Utility.getStatisticValue(outnums, Tol=False)
                for label, result in results.items():
                    features[u'20--F'+str(TCPNum)+'oPFS'+label] = round(result,3)
                
            if Alter:
                alterCon = []
                num=20
                sbin = int(len(nums)/num)
                for con in range(num):
                    alterCon.append(np.sum(outnums[con*sbin:(con+1)*sbin]))
                
                for i in range(len(alterCon)):
                    if alterCon[i] != 0:
                        features[u'23--FoAPS'+str(i)] = alterCon[i]

                results = Utility.getStatisticValue(alterCon)
                for label, result in results.items():
                    features[u'23--FoAPS'+str(label)]=result
    
    ## get packet info from first N tcp connection of first M Packets


## initial packets from first M packets of first N TCP connections
def getInitialPackets(features, trace, TCPNum=None, PacketNum=None, In=True, Out=True, Tol=True, Overall=True, firstN=True):
    pNum = 30
    if Overall:
        if Tol:
            packets = trace.getPackets()[:pNum]
            for i in range(len(packets)):
                features[u'24--IP'+str(i)] = packets[i]
        if In:
            packets = trace.getPackets(direction=Packet.Incoming)[:pNum]
            for i in range(len(packets)):
                features[u'25--iIP'+str(i)] = packets[i]
        if Out:
            packets = trace.getPackets(direction=Packet.Outgoing)[:pNum]
            for i in range(len(packets)):
                features[u'26--oIP'+str(i)] = packets[i]
    if firstN:
        if Tol:
            packets = trace.getPackets(TCPNum=TCPNum, PacketNum=PacketNum)[:pNum]
            for i in range(len(packets)):
                features[u'24--FIP'+str(i)] = packets[i]
        if In:
            packets = trace.getPackets(TCPNum=TCPNum, PacketNum=PacketNum, direction=Packet.Incoming)[:pNum]
            for i in range(len(packets)):
                features[u'25--FiIP'+str(i)] = packets[i]
        if Out:
            packets = trace.getPackets(TCPNum=TCPNum, PacketNum=PacketNum, direction=Packet.Outgoing)[:pNum]
            for i in range(len(packets)):
                features[u'26--FoIP'+str(i)] = packets[i]
            
def getInitialPackets_TCP(features, trace, TCPNum, PacketNum, Tol=True, In=True, Out=True):
    for i in range(0, min(trace.getTcpConsNum(), TCPNum)):
        for j in range(0,PacketNum):
            if Tol:
                features[u'27--IPT'+str(i)+'-P'+str(j)] = trace.packetSizeinNTCP(i, j)
            if In:
                features[u'28--iIPT'+str(i)+'-P'+str(j)] = trace.packetSizeinNTCP(i, j, Packet.Incoming)
            if Out:
                features[u'29--oIPT'+str(i)+'-P'+str(j)] = trace.packetSizeinNTCP(i, j, Packet.Outgoing)
                

def getPacketOrder(features, trace, TCPNum=None, PacketNum=None,In=True,Out=True, Overall=True, firstN=True, Loc=True, PreLoc=True):
    if Overall:
        [outPacketLoc, outPreLoc, inPacketLoc, inPreLoc] = trace.getTransposition()
        if Out:
            if Loc:
                for i in range(len(outPacketLoc)):
                    if outPacketLoc[i] != 0:
                        features[u'30--oPL'+str(i)] = outPacketLoc[i]


                results = Utility.getStatisticValue(outPacketLoc)
                for label, result in results.items():
                    features[u'30--oPL'+label] = result
            
            if PreLoc:    
                for i in range(len(outPreLoc)):
                    if outPreLoc[i] != 0:
                        features[u'31--oPLP'+str(i)] = outPreLoc[i]

                results = Utility.getStatisticValue(outPreLoc)
                for label, result in results.items():
                    features[u'31--oPLP'+label] = result
                
        if In:
            if Loc:
                for i in range(len(inPacketLoc)):
                    if inPacketLoc[i] != 0:
                        features[u'32--iPL'+str(i)] = inPacketLoc[i]

                results = Utility.getStatisticValue(inPacketLoc)
                for label, result in results.items():
                    features[u'32--oPL'+label] = result
               
            if PreLoc:
                for i in range(len(inPreLoc)):
                    if outPreLoc[i] != 0:
                        features[u'33--oPLP'+str(i)] = inPreLoc[i]

                results = Utility.getStatisticValue(inPreLoc)
                for label, result in results.items():
                    features[u'33--oPLP'+label] = result
            
    if firstN:
        [outPacketLoc, outPreLoc, inPacketLoc, inPreLoc] = trace.getTransposition(TCPNum=TCPNum, PacketNum=PacketNum)
        if Out:
            if Loc:
                for i in range(len(outPacketLoc)):
                    if outPacketLoc[i] != 0:
                        features[u'30--FoPL'+str(i)] = outPacketLoc[i]

                results = Utility.getStatisticValue(outPacketLoc)
                for label, result in results.items():
                    features[u'30--FoPL'+label] = result
              
            if PreLoc:
                for i in range(len(outPreLoc)):
                    if outPreLoc[i] != 0:
                        features[u'31--FoPLP'+str(i)] = outPreLoc[i]

                results = Utility.getStatisticValue(outPreLoc)
                for label, result in results.items():
                    features[u'31--FoPLP'+label] = result
                
        if In:
            if Loc:
                for i in range(len(inPacketLoc)):
                    if inPacketLoc[i] != 0:
                        features[u'32--FiPL'+str(i)] = inPacketLoc[i]

                results = Utility.getStatisticValue(inPacketLoc)
                for label, result in results.items():
                    features[u'32--FoPL'+label] = result
               
            if PreLoc:
                for i in range(len(inPreLoc)):
                    if outPreLoc[i] != 0:
                        features[u'33--FoPLP'+str(i)] = inPreLoc[i]

                results = Utility.getStatisticValue(inPreLoc)
                for label, result in results.items():
                    features[u'33--FoPLP'+label] = result
                

## average inter-arrival time of first N packets
def getAverageInterPacketTime(features, trace, InterNum=20, TCPNum=None, Tol=True, In=True, Out=True, Overall=True, firstN=True):
    if Overall:
        if Tol:
            averageTime = trace.averageInterpacketTime(InterNum=InterNum)
            for i in range(len(averageTime)): 
                if averageTime[i] != 0: 
                    features[u'34--InP'+ str(i)] = averageTime[i]
                    
        if In:
            averageTime=trace.averageInterpacketTime(InterNum=InterNum, direction=Packet.Incoming)
            for i in range(len(averageTime)): 
                if averageTime[i] != 0: 
                    features[u'35--iInP'+ str(i)] = averageTime[i]
                    
        if Out:
            averageTime=trace.averageInterpacketTime(InterNum=InterNum, direction=Packet.Outgoing)
            for i in range(len(averageTime)): 
                if averageTime[i] != 0: 
                    features[u'36--oInP'+ str(i)] = averageTime[i]
       
    if firstN:
        if Tol:
            averageTime = trace.averageInterpacketTime(TCPNum=TCPNum, InterNum=InterNum)
            for i in range(len(averageTime)): 
                if averageTime[i] != 0: 
                    features[u'34--F'+str(TCPNum)+'InP'+ str(i)] = averageTime[i]
        if In:
            averageTime=trace.averageInterpacketTime(InterNum=InterNum,TCPNum=TCPNum,direction=Packet.Incoming)
            for i in range(len(averageTime)): 
                if averageTime[i] != 0: 
                    features[u'35--F'+str(TCPNum)+'iInP'+ str(i)] = averageTime[i]
        if Out:
            averageTime=trace.averageInterpacketTime(InterNum=InterNum,TCPNum=TCPNum,direction=Packet.Outgoing)
            for i in range(len(averageTime)): 
                if averageTime[i] != 0: 
                    features[u'36--F'+str(TCPNum)+'oInP'+ str(i)] = averageTime[i]
            
## average inter-packet time per TCP connection or from first N TCP connections or from first M packets in each TCP
def getAverageInterPacketTimeTCP(features,trace,TCPNum=None,InterNum=None,Tol=True,In=True,Out=True,Overall=True,firstN=True):
    if Overall:
        if Tol:
            averTimeTCP = trace.averageInterpacketTimePerTCP()
            for i in range(min(len(averTimeTCP), 200)):
                features[u'37--InPT'+str(i)] = averTimeTCP[i]
                
            results = Utility.getStatisticValue(averTimeTCP)
            for label, result in results.items():
                features[u'37--'+label+'InPT'] = round(result,3)
        if In:
            averTimeTCP = trace.averageInterpacketTimePerTCP(direction=Packet.Incoming)
            for i in range(min(len(averTimeTCP), 200)):
                features[u'38--iInPT'+str(i)] = averTimeTCP[i]
                
            results = Utility.getStatisticValue(averTimeTCP)
            for label, result in results.items():
                features[u'38--'+label+'iInPT'] = round(result,3)
                
        if Out:
            averTimeTCP = trace.averageInterpacketTimePerTCP(direction=Packet.Outgoing)
            for i in range(min(len(averTimeTCP), 200)):
                features[u'39--oInPT'+str(i)] = averTimeTCP[i]
                
            results = Utility.getStatisticValue(averTimeTCP)
            for label, result in results.items():
                features[u'39--'+label+'oInPT'] = round(result,3)
    
    if firstN:
        if Tol:
            averTimeTCP = trace.averageInterpacketTimePerTCP(TCPNum=TCPNum, InterNum=InterNum)
            results = Utility.getStatisticValue(averTimeTCP)
            if InterNum or not Overall:
                for i in range(len(averTimeTCP)):
                    features[u'37--FInPT'+str(i)] = averTimeTCP[i]
                    
            for label, result in results.items():
                features[u'37--F'+str(TCPNum)+label+'InPT'] = round(result,3)
                
        if In:
            averTimeTCP = trace.averageInterpacketTimePerTCP(TCPNum=TCPNum, InterNum=InterNum, direction=Packet.Incoming)
            results = Utility.getStatisticValue(averTimeTCP)
            if InterNum or not Overall:
                for i in range(len(averTimeTCP)):
                    features[u'38--FiInPT'+str(i)] = averTimeTCP[i]
                    
            for label, result in results.items():
                features[u'38--F'+str(TCPNum)+label+'iInPT'] = round(result,3)
                
        if Out:
            averTimeTCP = trace.averageInterpacketTimePerTCP(TCPNum=TCPNum, InterNum=InterNum, direction=Packet.Outgoing)
            results = Utility.getStatisticValue(averTimeTCP)
            if InterNum or not Overall:
                for i in range(len(averTimeTCP)):
                    features[u'39--FoInPT'+str(i)] = averTimeTCP[i]
                    
            for label, result in results.items():
                features[u'39--F'+str(TCPNum)+label+'oInPT'] = round(result,3)

## overrall average inter-packet time
## unnecessary in encryted channel
def getAverageInterPacketTimeTrace(features,trace,TCPNum=None,InterNum=None,In=True,Out=True,Tol=True,Overall=True,firstN=True):
    if Overall:
        if Tol:
            features[u'40--aInPT'] = trace.averageInterpacketTimeTCP()
        if In:
            features[u'41--aiInPT'] = trace.averageInterpacketTimeTCP(direction=Packet.Incoming)
        if Out:
            features[u'42--aoInPT'] = trace.averageInterpacketTimeTCP(direction=Packet.Outgoing)
    
    if firstN:
        if Tol:
            features[u'40--F'+str(TCPNum)+'aInPT'] = trace.averageInterpacketTimeTCP(TCPNum=TCPNum,InterNum=InterNum)
        if In:
            features[u'41--F'+str(TCPNum)+'aiInPT'] = trace.averageInterpacketTimeTCP(TCPNum=TCPNum,InterNum=InterNum,direction=Packet.Incoming)
        if Out:
            features[u'42--F'+str(TCPNum)+'aoInPT'] = trace.averageInterpacketTimeTCP(TCPNum=TCPNum,InterNum=InterNum,direction=Packet.Outgoing)
    ## transmission time
    
def getTraceDuration(features,trace,TCPNum=None,PacketNum=None,Tol=True,In=True,Out=True,Overall=True,firstN=True):
    if Overall and trace.getTcpConsNum() > 0:
        if Tol:
            features[u'43--TD'] = trace.getDuration()
        if In:
            features[u'44--iTD'] = trace.getDuration(direction=Packet.Incoming)
        if Out:
            features[u'45--oTD'] = trace.getDuration(direction=Packet.Outgoing)
        
    if firstN:
        if Tol:
            features[u'43--FTD'] = trace.getDuration(TCPNum=TCPNum,PacketNum=PacketNum)
        if In:
            features[u'44--FiTD'] = trace.getDuration(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Incoming)
        if Out:
            features[u'45--FiTD'] = trace.getDuration(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Outgoing)

## get the start, end time and duration of N TCP connection
def getTCPTime(features, trace, ST=True, ET=True, DT=True, Ratio=True, TCPNum=None, Overall=True):
    if ST: 
        startTimes = trace.startTimeperTcp(normalized=Ratio)
        if Overall:
            for i in range(min(len(startTimes),200)): 
                features[u'46--'+str(i)+'STT'] = startTimes[i]
            
            results = Utility.getStatisticValue(startTimes)
            for label, result in results.items():
                features[u'46--'+label+'STT'] = round(result,3)
        
        if TCPNum:
            if not Overall:
                for i in range(min(len(startTimes),TCPNum)): 
                    features[u'46--F'+str(i)+'STT'] = startTimes[i]
                
            results = Utility.getStatisticValue(startTimes[:TCPNum])
            for label, result in results.items():
                features[u'46--F'+str(TCPNum)+label+'STT'] = round(result,3)
            
    if ET: 
        endTimes = trace.endTimeperTcp(normalized=Ratio)
        if Overall:   
            for i in range(min(len(endTimes), 200)): 
                features[u'47--'+str(i)+'ETT'] = endTimes[i]
                
            results = Utility.getStatisticValue(endTimes)
            for label, result in results.items():
                features[u'47--'+label+'ETT'] = round(result,3)
        
        if TCPNum:
            if not Overall:
                for i in range(min(len(endTimes), TCPNum)): 
                    features[u'47--F'+str(i)+'ETT'] = endTimes[i]
                    
            results = Utility.getStatisticValue(endTimes[:TCPNum])
            for label, result in results.items():
                features[u'47--F'+str(TCPNum)+label+'ETT'] = round(result,3)
            
    if DT:
        durations = trace.durTimeperTcp(normalized=Ratio)
        if Overall:
            for i in range(min(len(durations), 200)): 
                features[u'48--'+str(i)+'DTT'] = durations[i]

            results = Utility.getStatisticValue(durations)
            for label, result in results.items():
                features[u'48--'+label+'DTT'] = round(result,3)
                
        if TCPNum:
            if not Overall:
                for i in range(min(len(durations), TCPNum)): 
                    features[u'48--F'+str(i)+'DTT'] = durations[i]

            results = Utility.getStatisticValue(durations[:TCPNum])
            for label, result in results.items():
                features[u'48--F'+str(TCPNum)+label+'DTT'] = round(result,3)
        
## get incoming bytes, outgoing bytes
def getTCPBytes(features, trace, Tol=True, In=True, Out=True, Ratio=True, TCPNum=None, \
                Overall=True, TT=True, TI=True, TO=True):
    #features[u'49--NT'] = trace.getTcpConsNum()
    if In:
        inBytes = trace.getBytesTCP(direction=Packet.Incoming)
        if Overall:
            for i in range(min(len(inBytes), 200)): 
                features[u'50--'+str(i)+'iBT'] = inBytes[i]
            
            results = Utility.getStatisticValue(inBytes)
            for label, result in results.items(): 
                features[u'50--'+label + 'iBT'] = result
                
            if TI:
                for i, s in enumerate(sorted(inBytes, reverse=True)[:20]):
                    features[u'100--iT'+str(i)] = s
                
        if TCPNum:
            if not Overall:
                for i in range(min(len(inBytes), TCPNum)): 
                    features[u'50--F'+str(i)+'iBT'] = inBytes[i]
                    
            results = Utility.getStatisticValue(inBytes[:TCPNum])
            for label, result in results.items(): 
                features[u'50--F'+str(TCPNum)+label+'iBT'] = result
                
            if not Overall and TI:
                for i, s in enumerate(sorted(inBytes[:TCPNum], reverse=True)[:20]):
                    features[u'100--F'+str(TCPNum)+'-iT-'+str(i)] = s
                 
            
    if Out:
        outBytes = trace.getBytesTCP(direction=Packet.Outgoing)
        if Overall:
            for i in range(min(len(outBytes), 200)): 
                features[u'51--'+str(i)+'oBT'] = outBytes[i]
           
                
            results = Utility.getStatisticValue(outBytes)
            for label, result in results.items(): 
                features[u'51--'+label + 'oBT'] = result
                
            if TO:
                for i, s in enumerate(sorted(outBytes, reverse=True)[:20]):
                    features[u'101--oT'+str(i)] = s
                
        if TCPNum:
            if not Overall:
                for i in range(min(len(outBytes), TCPNum)): 
                    features[u'51--F'+str(i)+'oBT'] = outBytes[i]
                    
            results = Utility.getStatisticValue(outBytes[:TCPNum])
            for label, result in results.items(): 
                features[u'51--F'+str(TCPNum)+label+'oBT'] = result
   
    if Tol:
        Bytes = trace.getBytesTCP()
        if Overall:
            for i in range(min(len(Bytes), 200)): 
                features[u'52--'+str(i)+'BT'] = Bytes[i]
                
            results = Utility.getStatisticValue(Bytes)
            for label, result in results.items():
                features[u'52--'+label + 'BT'] = result  
                
            if TT:
                for i, s in enumerate(sorted(Bytes, reverse=True)[:20]):
                    features[u'102--T'+str(i)] = s
        
        if TCPNum:
            if not Overall:
                for i in range(min(len(Bytes), TCPNum)): 
                    features[u'52--F'+str(i)+'BT'] = outBytes[i]
                    
                if TT:
                    for i, s in enumerate(sorted(Bytes[:TCPNum], reverse=True)[:20]):
                        features[u'102--F'+str(TCPNum)+'-oT-'+str(i)] = s
                
            results = Utility.getStatisticValue(Bytes[:TCPNum])
            for label, result in results.items():
                features[u'52--F'+str(TCPNum)+label+'BT'] = result
                
    if Ratio:
        ratio = trace.getInBytesRatio()
        if Overall:
            for i in range(min(len(ratio), 200)): 
                features[u'53--'+str(i)+'irBT'] = ratio[i]
                
            results = Utility.getStatisticValue(ratio)
            for label, result in results.items():
                features[u'53--'+label + 'irBT'] = round(result,3)
                
        if TCPNum:
            if not Overall:
                for i in range(min(len(ratio), TCPNum)): 
                    features[u'53--F'+str(i)+'irBT'] = ratio[i]
                    
            results = Utility.getStatisticValue(ratio[:TCPNum])
            for label, result in results.items():
                features[u'53--F'+str(TCPNum)+label+'irBT'] = round(result,3)

def burstInfo(trace, TCPNum=None, PacketNum=None, rvalue=600, Overall=True, firstN=True):
#     trace.reorderTCPCons()
    if Overall:
        trace.getBurstInfo(rvalue)
        
    if PacketNum:
        trace.getBurstInfo_N(rvalue=rvalue, TCPNum=TCPNum, PacketNum=PacketNum)
        
    ## get burst size count and unique burst size
def getBurstSizeCount(features,trace,rvalue,TCPNum=None,PacketNum=None,Count=True,Unique=True,Overall=True,firstN=True):
    if Overall:
        if trace.burstCount: 
            for index, bcount in trace.burstCount.items(): 
                if Count: 
                    features[u'54--BC' + str(index)] = bcount
                if Unique: 
                    features[u'55--UB' + str(index)] = 1
                    
    if firstN:
        if PacketNum:
            if trace.FburstCount:
                for size, bcount in trace.FburstCount.items():
                    if Count:
                        features[u'54--F'+str(PacketNum)+'BC'+str(size)] = bcount
                    if Unique:
                        features[u'55--F'+str(PacketNum)+'UB'+str(size)] = 1
                        
        else:
            counts = trace.getTraceCount(TCPNum)
            for size, bcount in counts.items():
                if Count:
                    features[u'54--F'+str(PacketNum)+'BC'+str(size)] = bcount
                if Unique:
                    features[u'55--F'+str(PacketNum)+'UB'+str(size)] = 1
                        
## get information about number of burst
def getBurstNum(features,trace,TCPNum=None,PacketNum=None,Tol=True,In=True,Out=True,Ratio=True,Overall=True,firstN=True):
    if In:
        if Overall:
            inBurstNum = trace.getBurstNum(direction=Packet.Incoming)
            for i in range(min(len(inBurstNum), 200)): 
                features[u'56--'+str(i)+'iBN'] = inBurstNum[i]
                
            results = Utility.getStatisticValue(inBurstNum)
            for label, result in results.items():
                features[u'56--'+label+'iBN'] = result
        
        if firstN:
            f_inBurstNum = trace.getBurstNum(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Incoming)
            if not Overall:
                for i in range(min(len(f_inBurstNum), 200)): 
                    features[u'56--F'+str(i)+'iBN'] = f_inBurstNum[i]
                    
            results = Utility.getStatisticValue(f_inBurstNum)
            for label, result in results.items():
                features[u'56--F'+str(TCPNum)+label+'iBN'] = result
            
    if Out:
        if Overall:
            outBurstNum = trace.getBurstNum(direction=Packet.Outgoing)
            for i in range(min(len(outBurstNum), 200)): 
                features[u'57--'+str(i)+'oBN'] = outBurstNum[i]
                
            results = Utility.getStatisticValue(outBurstNum)
            for label, result in results.items():
                features[u'57--'+label+'oBN'] = result 
                
        if firstN:
            f_outBurstNum = trace.getBurstNum(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Outgoing)
            
            if not Overall:
                for i in range(min(len(f_outBurstNum), 200)): 
                    features[u'57--F'+str(i)+'oBN'] = f_outBurstNum[i]
                    
            results = Utility.getStatisticValue(f_outBurstNum)
            for label, result in results.items():
                features[u'57--F'+str(TCPNum)+label+'oBN'] = result
    
    if Tol:
        if Overall:
            burstNum = trace.getBurstNum()
            for i in range(min(len(burstNum), 200)): 
                features[u'58--'+str(i)+'BN'] = burstNum[i]
                
            results = Utility.getStatisticValue(burstNum)
            for label, result in results.items():
                features[u'58--'+label+'BN'] = result  
                
        if firstN:
            f_burstNum = trace.getBurstNum(TCPNum=TCPNum,PacketNum=PacketNum)
            if not Overall:
                for i in range(min(len(f_burstNum), 200)): 
                    features[u'58--F'+str(i)+'BN'] = f_burstNum[i]
                    
            results = Utility.getStatisticValue(f_burstNum)
            for label, result in results.items():
                features[u'58--F'+str(TCPNum)+label+'BN'] = result
    
    if Ratio:
        if Overall:
            if not Tol:
                burstNum = trace.getBurstNum()
            if not In:
                inBurstNum = trace.getBurstNum(direction=Packet.Incoming)

            totalnum = np.sum(burstNum)
            if totalnum:
                innum = np.sum(inBurstNum)
                features[u'59--riBN'] = round(innum/totalnum,3) 
        
                ratio = trace.getBurstNumRatio()
                for i in range(min(len(ratio), 200)): 
                    features[u'59--'+str(i)+'riBN'] = ratio[i]
                
                results = Utility.getStatisticValue(ratio)  
                for label, result in results.items():
                    features[u'59--'+label+'riBN'] = round(result,3)
                
        if firstN:
            f_totalnum = np.sum(f_burstNum)
            if not Tol:
                f_burstNum = trace.getBurstNum(TCPNum=TCPNum,PacketNum=PacketNum)
            if not In:
                f_inBurstNum = trace.getBurstNum(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Incoming)
            if f_totalnum!=0:
                f_innum = np.sum(f_inBurstNum)
                features[u'59--F'+str(TCPNum)+'riBN'] = round(f_innum/f_totalnum,3)
                
                f_ratio = trace.getBurstNumRatio(TCPNum=TCPNum, PacketNum=PacketNum)
                if not Overall:
                    for i in range(min(len(f_ratio), 200)): 
                        features[u'59--F'+str(i)+'riBN'] = f_ratio[i]
                    
                results = Utility.getStatisticValue(f_ratio)
                for label, result in results.items():
                    features[u'59--F'+str(TCPNum)+label+'riBN'] = result
        
## get burst duration
def getBurstDuration(features,trace,TCPNum=None,PacketNum=None,Tol=True,In=True,Out=True,Overall=True,firstN=True):
    if Tol:
        if Overall:
            durations = trace.getBurstDuration()
            results = Utility.getStatisticValue(durations)
            for label, result in results.items():
                features[u'60--'+label + 'BD'] = result
                
        if firstN:
            durations = trace.getBurstDuration(TCPNum=TCPNum, PacketNum=PacketNum)
            results = Utility.getStatisticValue(durations)
            for label, result in results.items():
                features[u'60--F' + str(TCPNum) + label + 'BD'] = result
            
    if In:
        if Overall:
            durations = trace.getBurstDuration(direction=Packet.Incoming)
            results = Utility.getStatisticValue(durations)
            for label, result in results.items():
                features[u'61--'+label + 'iBD'] = result
                
        if firstN:
            durations = trace.getBurstDuration(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Incoming)
            results = Utility.getStatisticValue(durations)
            for label, result in results.items():
                features[u'61--F' + str(TCPNum) + label + 'iBD'] = result
            
    if Out:
        if Overall:
            durations = trace.getBurstDuration(direction=Packet.Outgoing)
            results = Utility.getStatisticValue(durations)
            for label, result in results.items():
                features[u'62--'+label + 'oBD'] = result
                
        if firstN:
            durations = trace.getBurstDuration(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Outgoing)
            results = Utility.getStatisticValue(durations)
            for label, result in results.items():
                features[u'62--F' + str(TCPNum) + label + 'oBD'] = result
    
## statistic about bytes in burst
def getBurstBytes(features,trace,TCPNum=None,PacketNum=None,Tol=True,In=True,Out=True,Overall=True,firstN=True):
    if In:
        if Overall:
            results = Utility.getStatisticValue(trace.inBurstBytes)
            for label, result in results.items():
                features[u'63--'+label+'iBB'] = result
                
        if firstN:
            inBurstBytes = trace.getBurstBytes(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Incoming)
            results = Utility.getStatisticValue(inBurstBytes)
            for label, result in results.items():
                features[u'63--F'+str(TCPNum)+label+'iBB'] = result
            
    if Out:
        if Overall:
            results = Utility.getStatisticValue(trace.outBurstBytes)
            for label, result in results.items():
                features[u'64--'+label+'oBB'] = result
                
        if firstN:
            outBurstBytes = trace.getBurstBytes(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Outgoing)
            results = Utility.getStatisticValue(outBurstBytes)
            for label, result in results.items():
                features[u'64--F'+str(TCPNum)+label+'oBB'] = result
            
    if Tol:
        if Overall:
            results = Utility.getStatisticValue(trace.inBurstBytes+trace.outBurstBytes)
            for label, result in results.items():
                features[u'65--'+label+'BB'] = result
                
        if firstN:
            if not In:
                inBurstBytes = trace.getBurstBytes(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Incoming)
            if not Out:
                outBurstBytes = trace.getBurstBytes(TCPNum=TCPNum,PacketNum=PacketNum,direction=Packet.Outgoing)
                
            results = Utility.getStatisticValue(outBurstBytes+inBurstBytes)
            for label, result in results.items():
                features[u'65--F'+str(TCPNum)+label+'BB'] = result

## packet number in TCP
def getPacketNumBurst(features,trace,TCPNum=None,PacketNum=None,Tol=True,In=True,Out=True,Overall=True,firstN=True):
    if Tol: 
        if Overall:
            pNumBurst = trace.getPacketNumBurst()
            for pnum, count in enumerate(Counter(pNumBurst)):
                features[u'66--PNBC'+ str(pnum)] = Utility.roundnumMarkers(count)

            results = Utility.getStatisticValue(pNumBurst, Tol=False)
            for label, result in results.items():
                features[u'69--'+label+'PNB'] = result
                
        if firstN:
            pNumBurst = trace.getPacketNumBurst(TCPNum=TCPNum,PacketNum=PacketNum)
            for pnum, count in enumerate(Counter(pNumBurst)):
                features[u'66--F'+str(TCPNum)+'PNBC'+str(pnum)] = Utility.roundnumMarkers(count)

            results = Utility.getStatisticValue(pNumBurst, Tol=False)
            for label, result in results.items():
                features[u'69--F'+str(TCPNum)+label+'PNB'] = result

    if In:
        if Overall:
            pNumBurst = trace.getPacketNumBurst(direction=Packet.Incoming)
            for pnum, count in enumerate(Counter(pNumBurst)):
                features[u'67--iPNBC'+ str(pnum)] = Utility.roundnumMarkers(count)

            results = Utility.getStatisticValue(pNumBurst, Tol = False)
            for label, result in results.items():
                features[u'70--'+label+'iPNB'] = result
                
        if firstN:
            pNumBurst = trace.getPacketNumBurst(TCPNum=TCPNum,PacketNum=PacketNum, direction=Packet.Incoming)
            for pnum, count in enumerate(Counter(pNumBurst)):
                features[u'67--F'+str(TCPNum)+'iPNBC'+str(pnum)] = Utility.roundnumMarkers(count)

            results = Utility.getStatisticValue(pNumBurst, Tol=False)
            for label, result in results.items():
                features[u'70--F'+str(TCPNum)+label+'iPNB'] = result
            
    if Out:
        if Overall:
            pNumBurst = trace.getPacketNumBurst(direction=Packet.Outgoing)
            for pnum, count in enumerate(Counter(pNumBurst)):
                features[u'68--oPNBC'+ str(pnum)] = Utility.roundnumMarkers(count)

            results = Utility.getStatisticValue(pNumBurst, Tol = False)
            for label, result in results.items():
                features[u'71--'+label+'oPNB'] = result
                
        if firstN:
            pNumBurst = trace.getPacketNumBurst(TCPNum=TCPNum,PacketNum=PacketNum, direction=Packet.Outgoing)
            for pnum, count in enumerate(Counter(pNumBurst)):
                features[u'68--F'+str(TCPNum)+'oPNBC'+str(pnum)] = Utility.roundnumMarkers(count)

            results = Utility.getStatisticValue(pNumBurst, Tol=False)
            for label, result in results.items():
                features[u'71--F'+str(TCPNum)+label+'oPNB'] = result

## initial bursts
def getInitialBursts_TCP(features, trace, TCPNum, BurstNum, Tol=True, In=True, Out=True):
    TCPIndex = 0
    for timeTCP in trace.timeInfoPerTcp[:TCPNum]:
        if TCPIndex >= TCPNum: 
            break
        n0 = 0
        n1 = 0
        n2 = 0
        for time, BSize in trace.burstOrder_TCP[timeTCP].items():
            if Tol and n0 < BurstNum:
                features[u'72--IB'+str(TCPIndex) + 'T' + str(n0) + 'B'] = BSize
                n0 += 1
            if In and n1 < BurstNum and BSize > 0:
                features[u'73--iIB'+str(TCPIndex) + 'T' + str(n1) + 'B'] = BSize
                n1 += 1
            
            if Out and n2 < BurstNum and BSize < 0:
                features[u'74--oIB'+str(TCPIndex) + 'T' + str(n2) + 'B'] = BSize
                n2 += 1
        TCPIndex += 1
        
def getInitialBursts(features, trace, BurstNum, TCPNum=None,PacketNum=None, Tol=True, In=True, Out=True, Overall=True, firstN=True):
    if Overall:
        if Tol:
            n=0
            bursts = trace.getBurstOrder(BurstNum=BurstNum)
            for Bsize in bursts:
                features[u'75--IBT' + str(n) + 'B'] = Bsize
                n+=1
        if In:
            n=0
            bursts = trace.getBurstOrder(BurstNum=BurstNum, direction=Packet.Incoming)
            for Bsize in bursts:
                features[u'76--iIBT' + str(n) + 'B'] = Bsize
                n+=1
        if Out:
            n=0
            bursts = trace.getBurstOrder(BurstNum=BurstNum, direction=Packet.Outgoing)
            for Bsize in bursts:
                features[u'77--oIBT' + str(n) + 'B'] = Bsize
                n+=1
    if firstN:
        if Tol:
            n=0
            bursts = trace.getBurstOrder(BurstNum=BurstNum, TCPNum=TCPNum, PacketNum=PacketNum)
            for Bsize in bursts:
                features[u'75--FIBT' + str(n) + 'B'] = Bsize
                n+=1
        if In:
            n=0
            bursts = trace.getBurstOrder(BurstNum=BurstNum, TCPNum=TCPNum, PacketNum=PacketNum, direction=Packet.Incoming)
            for Bsize in bursts:
                features[u'76--FiIBT' + str(n) + 'B'] = Bsize
                n+=1
        if Out:
            n=0
            bursts = trace.getBurstOrder(BurstNum=BurstNum, TCPNum=TCPNum, PacketNum=PacketNum, direction=Packet.Outgoing)
            for Bsize in bursts:
                features[u'77--FoIBT' + str(n) + 'B'] = Bsize
                n+=1
                
def getHTMLSize(features, trace,TCPNum=None,PacketNum=None,Overall=True, firstN=True):
    if Overall:
        #for time in sorted(trace.htmlInfo_TCP.keys()):
        #    features[u'78--HS'] = trace.htmlInfo_TCP[time]
        #    break

        results = Utility.getStatisticValue(list(trace.htmlInfo_TCP.values()))
        for label, result in results.items(): 
            features[u'79--'+label + 'HS'] = result
            
    if firstN:
        htmlsize = trace.getHtmlSizeTCP(TCPNum=TCPNum, PacketNum=PacketNum)
        results = Utility.getStatisticValue(htmlsize)
        for label, result in results.items(): 
            features[u'79--F'+ str(TCPNum) + label + 'HS'] = result 
            
def getPortCount(features, trace, TCPNum=None, Count=True, Unique=True, Overall=True, firstN=True):
    if Overall:
        portCount = trace.getPortCount()
        if portCount:
            features[u'98--PC'] = len(portCount)
        for port, pcount in portCount.items():
            if Count: 
                features[u'80--PC' + str(port)] = pcount
            if Unique: 
                features[u'81--UP' + str(port)] = 1
    if firstN:
        portCount = trace.getPortCount(TCPNum=TCPNum)
        if portCount:
            features[u'98--FPC'] = len(portCount)
        for port, pcount in portCount.items():
            if Count: 
                features[u'80-F'+str(TCPNum)+'PC'+str(port)] = pcount
            if Unique: 
                features[u'81--F'+str(TCPNum)+'NP'+str(port)] = 1
                
def getPortBytes(features, trace, portIds=portIds, TCPNum=None, PacketNum=None,Tol=True, In=True, Out=True, Ratio=True, Overall=True, firstN=True):
    if Overall:
        portBytes,inPortBytes,outPortBytes = trace.getPortBytes()
        
        for portId in portIds:
            if Tol:
                results = Utility.getStatisticValue(portBytes[portId])
                for label, result in results.items():
                    features[u'82--'+label+'BPID'+str(portId)] = result 
            if In:
                results = Utility.getStatisticValue(inPortBytes[portId])
                for label, result in results.items():
                    features[u'83--'+label+'iBPID'+str(portId)] = result
            if Out:
                results = Utility.getStatisticValue(outPortBytes[portId])
                for label, result in results.items():
                    features[u'84--'+label+'oBPID'+str(portId)] = result
                    
            if Ratio:
                totalBytes = np.sum(portBytes[portId])
                inBytes = np.sum(inPortBytes[portId])
                if totalBytes != 0 and inBytes != 0:
                    features[u'85--'+label+'riBPID'+str(portId)] = round(inBytes/totalBytes, 3)
    if firstN:
        portBytes,inPortBytes,outPortBytes = trace.getPortBytes(TCPNum=TCPNum,PacketNum=PacketNum)
        
        for portId in portIds:
            if Tol:
                results = Utility.getStatisticValue(portBytes[portId])
                for label, result in results.items():
                    features[u'82--F'+str(TCPNum)+label+'BPID'+str(portId)] = result  
            if In:
                results = Utility.getStatisticValue(inPortBytes[portId])
                for label, result in results.items():
                    features[u'83--F'+str(TCPNum)+label+'iBPID'+str(portId)] = result
            if Out:
                results = Utility.getStatisticValue(outPortBytes[portId])
                for label, result in results.items():
                    features[u'84--F'+str(TCPNum)+label+'oBPID'+str(portId)] = result 
                    
            if Ratio:
                totalBytes = np.sum(portBytes[portId])
                inBytes = np.sum(inPortBytes[portId])
                if totalBytes != 0 and inBytes != 0:
                    features[u'85--F'+str(TCPNum)+label+'riBPID'+str(portId)] = round(inBytes/totalBytes,3)
        
def getServerAddressCount(features,trace,TCPNum=None,Count=True,Unique=True,Overall=True,firstN=True,threeField=True,Tol=True,Top=True,Anonymize=False):
    
    if Overall:
        addrCount = trace.serverAddrCount(threeField=threeField)
        if Tol and addrCount:
            features[u'97-TS'] = len(addrCount)
         
        if Top:
            for i, scount in enumerate(sorted(addrCount.values(), reverse=True)[:20]):
                features[u'110--AAC'+str(i)] = scount
        
        if not Anonymize:
            for address, scount in addrCount.items():
                if Count: 
                    features[u'86-AC'+address] = scount
                if Unique: 
                    features[u'87-UA'+address] = 1
    if firstN:
        addrCount = trace.serverAddrCount(threeField=threeField, TCPNum=TCPNum)
        if Tol and addrCount:
            features[u'97--F'+str(TCPNum)+'TS'] = len(addrCount)
            
        if Top:
            for i, scount in enumerate(sorted(addrCount.values(), reverse=True)[:20]):
                features[u'110--F'+str(TCPNum)+'AAC'+str(i)] = scount
        
        if not Anonymize:
            for address, scount in addrCount.items():
                if Count: 
                    features[u'86--F'+str(TCPNum)+'AC'+str(address)] = scount
                if Unique: 
                    features[u'87--F'+str(TCPNum)+'UA'+str(address)] = 1
            
#firstN=False, Tol=False, Ratio=False, TT=False, TI=False,TO=False
def getSeverAddressBytes(features, trace, IPAddress=None,TCPNum=None,PacketNum=None,Overall=True,firstN=True,Tol=True,\
                         In=True,Out=True, Ratio=True, TT=True, TI=True, TO=True):
    if Overall:
        addrBytes, inAddrBytes, outAddrBytes = trace.getServerAddrBytes()
         
        if TT:
            sum_packets = []
            for addr, info in addrBytes.items():
                sum_packets.append(sum(info))
            
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'103--T'+str(i)] = v
                
        if TI:
            sum_packets = []
            for addr, info in inAddrBytes.items():
                sum_packets.append(sum(info))
            
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'104--iT'+str(i)] = v
                
        if TO:
            sum_packets = []
            for addr, info in outAddrBytes.items():
                sum_packets.append(sum(info))
            
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'105--oT'+str(i)] = v
            
        for address in IPAddress:
            if address not in addrBytes.keys(): 
                continue
            
            if Tol:
                
                results = Utility.getStatisticValue(addrBytes[address])
                for label, result in results.items():
                    features[u'88--'+label+'SB'+address] = result

            if In:
                results = Utility.getStatisticValue(inAddrBytes[address])
                for label, result in results.items():
                    features[u'89--'+label+'iSB'+address] = result

            if Out:
                results = Utility.getStatisticValue(outAddrBytes[address])
                for label, result in results.items():
                    features[u'90--'+label+'oSB'+address] = result

            ssum = np.sum(addrBytes[address])
            if Ratio:
                if ssum > 0:
                    features[u'91--riSB'+address] = np.sum(inAddrBytes[address])/ssum
                    results = Utility.getStatisticValue([a/b for a,b in zip(inAddrBytes[address],addrBytes[address])])
                    for label, result in results.items():
                        features[u'91--'+label+'riSB'+address] = result
                        
    if firstN:
        addrBytes, inAddrBytes, outAddrBytes = trace.getServerAddrBytes(TCPNum=TCPNum,PacketNum=PacketNum)
        if TT:
            sum_packets = []
            for addr, info in addrBytes.items():
                sum_packets.append(sum(info))
            
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'103--F'+str(TCPNum)+'T'+str(i)] = v
                
        if TI:
            sum_packets = []
            for addr, info in inAddrBytes.items():
                sum_packets.append(sum(info))
            
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'104--F'+str(TCPNum)+'iT'+str(i)] = v
                
        if TO:
            sum_packets = []
            for addr, info in outAddrBytes.items():
                sum_packets.append(sum(info))
            
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'105--F'+str(TCPNum)+'oT'+str(i)] = v
                
        for address in IPAddress:
            if address not in addrBytes.keys(): 
                continue
            
            if Tol:
                results = Utility.getStatisticValue(addrBytes[address])
                for label, result in results.items():
                    features[u'88--F'+str(TCPNum)+label+'SB'+str(address)] = result

            if In:
                results = Utility.getStatisticValue(inAddrBytes[address])
                for label, result in results.items():
                    features[u'89--F'+str(TCPNum)+label+'iSB'+str(address)] = result  

            if Out:
                results = Utility.getStatisticValue(outAddrBytes[address])
                for label, result in results.items():
                    features[u'90--F'+str(TCPNum)+label+'oSB'+str(address)] = result 

            ssum = np.sum(addrBytes[address])
            if Ratio:
                if ssum > 0:
                    features[u'91--F'+str(TCPNum)+'riSB'+str(address)] = np.sum(inAddrBytes[address])/ssum
                    
                    r = []
                    for i in range(len(addrBytes[address])):
                        if addrBytes[address][i] !=0:
                            r.append(round(inAddrBytes[address][i]/addrBytes[address][i], 3))
                        else:
                            r.append(0)
                   
                    results = Utility.getStatisticValue(r)
                    for label, result in results.items():
                        features[u'91--F'+str(TCPNum)+label+'riSB'+str(address)] = result
                        
def getHostnameCount(features, trace, TCPNum=None,Overall=True,firstN=True,HC=True):
    if Overall:
        hostCount = trace.getHostnameCount()
        if HC and hostCount:
            features[u'99--HC'] = len(hostCount)
        for hostname, count in hostCount.items():
            features[u'92--'+hostname] = count
            
    if firstN:
        hostCount = trace.getHostnameCount(TCPNum=TCPNum)
        if HC and hostCount:
            features[u'99--F'+str(TCPNum)+'HC'] = len(hostCount)
            
        for hostname, count in hostCount.items():
            features[u'92--F'+str(TCPNum)+'-'+hostname] = count
            
def getHostNameBytes(features,trace, HOST_NAMES = None, TCPNum=None, PacketNum=None,Overall=True,firstN=True,Tol=True,\
                     In=True,Out=True, Ratio=True, TT=True, TI=True, TO=True):
    if Overall:
        hostBytes, inHostBytes, outHostBytes = trace.getHostnameBytes()
        if TT:
            sum_packets = []
            for addr, info in hostBytes.items():
                sum_packets.append(sum(info))
                
                
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'106--TH'+str(i)] = v
                
        if TI:
            sum_packets = []
            for addr, info in inHostBytes.items():
                sum_packets.append(sum(info))
                
                
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'107--iTH'+str(i)] = v
                
        if TO:
            sum_packets = []
            for addr, info in outHostBytes.items():
                sum_packets.append(sum(info))
                
                
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'108--oTH'+str(i)] = v
            
            
        for hostname in HOST_NAMES:
            if hostname not in hostBytes.keys():
                continue
                
            if Tol:
                results = Utility.getStatisticValue(hostBytes[hostname])
                for label, result in results.items():
                    features[u'93--'+label+'HB'+hostname] = result
                    
            if In:
                results = Utility.getStatisticValue(inHostBytes[hostname])
                for label, result in results.items():
                    features[u'94--'+label+'iHB'+hostname] = result
                    
            if Out:
                results = Utility.getStatisticValue(outHostBytes[hostname])
                for label, result in results.items():
                    features[u'95--'+label+'oHB'+hostname] = result
                    
                    
            ssum = np.sum(hostBytes[hostname])
            if Ratio:
                if ssum > 0:
                    features[u'96--riHB'+hostname] = np.sum(inHostBytes[hostname])/ssum
                    r = []
                    for i in range(len(hostBytes[hostname])):
                        if hostBytes[hostname][i] !=0:
                            r.append(round(inHostBytes[hostname][i]/hostBytes[hostname][i], 3))
                        else:
                            r.append(0)
                            
                    results = Utility.getStatisticValue(r)
                    for label, result in results.items():
                        features[u'96--'+label+'riHB'+hostname] = result
                    
    if firstN:
        hostBytes, inHostBytes, outHostBytes = trace.getHostnameBytes(TCPNum=TCPNum, PacketNum=PacketNum)
        if TT:
            sum_packets = []
            for addr, info in hostBytes.items():
                sum_packets.append(sum(info))
                
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'106--F'+str(TCPNum)+'-TH'+str(i)] = v
                
        if TI:
            sum_packets = []
            for addr, info in inHostBytes.items():
                sum_packets.append(sum(info))
                
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'107--F'+str(TCPNum)+'-iTH'+str(i)] = v
                
        if TO:
            sum_packets = []
            for addr, info in outHostBytes.items():
                sum_packets.append(sum(info))
                
            for i, v in enumerate(sorted(sum_packets, reverse=True)[:20]):
                features[u'108--F'+str(TCPNum)+'-oTH'+str(i)] = v
                
        for hostname in HOST_NAMES:
            if hostname not in hostBytes.keys():
                continue
                
            if Tol:
                results = Utility.getStatisticValue(hostBytes[hostname])
                for label, result in results.items():
                    features[u'93--'+label+'FHB'+hostname] = result
                    
            if In:
                results = Utility.getStatisticValue(inHostBytes[hostname])
                for label, result in results.items():
                    features[u'94--'+label+'FiHB'+hostname] = result
                    
            if Out:
                results = Utility.getStatisticValue(outHostBytes[hostname])
                for label, result in results.items():
                    features[u'95--'+label+'FoHB'+hostname] = result
                    
                    
            ssum = np.sum(hostBytes[hostname])
            if Ratio:
                if ssum > 0:
                    features[u'96--FriHB'+hostname] = np.sum(inHostBytes[hostname])/ssum
                    r = []
                    for i in range(len(hostBytes[hostname])):
                        if hostBytes[hostname][i] !=0:
                            r.append(round(inHostBytes[hostname][i]/hostBytes[hostname][i], 3))
                        else:
                            r.append(0)
                            
                    results = Utility.getStatisticValue(r)
                    for label, result in results.items():
                        features[u'96--'+label+'FriHB'+hostname] = result
                        
                        
                        
def getCUMULFeature(features, trace, featureCount = 100):
    import itertools
    cum = []
    total = []
    for packetsize in trace.getPackets():
        if len(cum) == 0:
            cum.append(packetsize)
            total.append(abs(packetsize))
        else:
            cum.append(cum[-1] + packetsize)
            total.append(total[-1] + abs(packetsize))

    if total:
        cumFeatures = np.interp(np.linspace(total[0], total[-1], featureCount+1), total, cum)
        for i, el in enumerate(itertools.islice(cumFeatures, 1, None)):
            features[u'120--cumul-'+str(i)] = el