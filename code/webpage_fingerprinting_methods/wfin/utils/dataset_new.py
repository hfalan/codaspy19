import sys, random, os, glob, pickle, json, random, Config, math
import pandas
import numpy as np
from collections import defaultdict

from Packet import Packet
from Trace import Trace
from TCPConnection import TCPConnection
import Utility

import featureExtraction


Config.hostname = dict() # hostname is used to extract features from hostname

def getTrace(visit_file, direction=None):
    with open(visit_file, 'r') as f:
        sample = json.load(f)

    Config.hostname.update(sample[u'ip_to_name'])
#     webId, traceId = sample['visit_log'][u'current_url'], sample['visit_log']['visit_id']
    webId, traceId = -1, sample['visit_log']['visit_id']
    
    trace = Trace(traceId, webId)
    for tcp_conn in sample['tcp_connections']:
        
        connection_id = tcp_conn['connection_id']
        
        TCP = TCPConnection(connection_id, webId, hostip=sample['visit_log'][u'host_ip'])

        for pkt in tcp_conn['packets']:
            pkt_time, pkt_size = pkt[0], abs(pkt[1])
            
            if pkt_size == 0:
                continue

            pkt_dir = Packet.Outgoing if pkt[1] < 0 else Packet.Incoming

            if direction is None or direction == pkt_dir:
                TCP.addPacket(Packet(pkt_time, pkt_size, pkt_dir))
                
        trace.addTcpCon(TCP)
        
    return trace

def get_features(visit_file, SERVER_ADDRESS, HOST_NAMES, direction=None):
    """
    visit_file : directory of a json file
    direction - (Packet.Incoming, Packet.Outgoing, None):
        consider only incoming or outgoing packets
    """
    features = defaultdict(list)
    trace = getTrace(visit_file, direction)
    
    features = defaultdict(list)
    featureExtraction.getPacketSizeCount(features,trace,rvalue=1,firstN=False, )
    featureExtraction.getPacketOrder(features,trace,firstN=False, )
    featureExtraction.getPacketNum(features,trace,firstN=False, Tol=False,In=False,Out=False)
    featureExtraction.getCumulatedPacketSize(features,trace,firstN=False, )
    featureExtraction.getInitialPackets(features,trace,firstN=False, )
    featureExtraction.getInitialPackets_TCP(features,trace,TCPNum=5,PacketNum=6)
    featureExtraction.getTCPBytes(features,trace,In=False,Tol=False,TT=False, TI=False, TO=False)
    featureExtraction.getOutConcentration(features,trace,firstN=False,)

    featureExtraction.burstInfo(trace)
    featureExtraction.getBurstSizeCount(features,trace,rvalue=600,firstN=False, )
    featureExtraction.getBurstNum(features,trace,firstN=False,)
    featureExtraction.getHTMLSize(features,trace,firstN=False,)
    
#     featureExtraction.getBurstBytes(features,trace,firstN=False, In=False, Tol=False)
    featureExtraction.getBurstBytes(features,trace,firstN=False, In=False)
    featureExtraction.getInitialBursts(features,trace,BurstNum=25,firstN=False,In=False)

#     featureExtraction.getSeverAddressBytes(features,trace,firstN=False, In=False, Tol=False, TT=False, TI=False,TO=False)
    #featureExtraction.getSeverAddressBytes(features,trace, IPAddress=SERVER_ADDRESS, firstN=False, Tol=False, Ratio=False, TT=False, TI=False,TO=False)
    featureExtraction.getSeverAddressBytes(features,trace, IPAddress=SERVER_ADDRESS, firstN=False, In=False, Tol=False, TT=False, TI=False,TO=False)
    ## one parameter of getSeverAddressBytes is IPAddress, which
    ## indicates top 20 server IP addresses in the dataset
    
    featureExtraction.getServerAddressCount(features,trace,firstN=False,Top=False,Count=False,Tol=False )
    

    
#     featureExtraction.getHostNameBytes(features,trace,firstN=False,TT=False, TI=False,TO=False, )
    featureExtraction.getHostNameBytes(features,trace,HOST_NAMES=HOST_NAMES, firstN=False,TT=False, TI=False,TO=False, )
    ## one parameter of getHostNameBytes is HOST_NAMES, which
    ## indicates top 20 hostnames in the dataset
    featureExtraction.getHostnameCount(features,trace,firstN=False, HC=False)
    
    featureExtraction.getPortBytes(features,trace,firstN=False,Tol=False,In=False )
    
    return features