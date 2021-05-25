from struct import pack

from Queue import Queue
from math import sqrt
import time

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.recoco import Timer

import requests as r
# POX IPv4 unpacking TOS is wrong. TOS is 6 bits and IPv4 stores the full byte
# We remove the 2 extra bits that are ECN (2 bits) field

log = {}


def getIPv4DSCP(ippkt):
    return ippkt.tos >> 2

def getIPV4HLen(ippkt):
    return ippkt.hl * 4

class TCPState:

    TCP_STATE_START = 0
    TCP_STATE_SYN = 1
    TCP_STATE_SYNACK = 2
    TCP_STATE_ESTABLISHED = 3
    TCP_STATE_FIN = 4
    TCP_STATE_CLOSED = 5

    def __init__(self):
        self.state = 0
    
    def tcpUpdate(self, tcppkt, dir, pdir):
        #log.debug('UPDATEING TCP STATE')
        if tcppkt.RST:
            self.state = TCPState.TCP_STATE_CLOSED
        elif tcppkt.FIN and dir == pdir:
            #log.debug('ABOUT TO CLOSE CONN TCP_FIN')
            self.state = TCPState.TCP_STATE_FIN
        elif self.state == TCPState.TCP_STATE_FIN:
            if tcppkt.ACK and dir != pdir:
                self.state = TCPState.TCP_STATE_CLOSED
        elif self.state == TCPState.TCP_STATE_START:
            if tcppkt.SYN and dir == pdir:
                self.state = TCPState.TCP_STATE_SYN
        elif self.state == TCPState.TCP_STATE_SYN:
            if tcppkt.SYN and tcppkt.ACK and dir != pdir:
                self.state = TCPState.TCP_STATE_SYNACK
        elif self.state == TCPState.TCP_STATE_SYNACK:
            if tcppkt.ACK and dir == pdir:
                self.state = TCPState.TCP_STATE_ESTABLISHED
        
        #log.debug('NewState: ' + str(self.state))


# Features correspond to Forward Packets and Backward Packets of the flow
ALL_FEATURE_NAMES = [
    'TOTAL_FPACKETS', 'TOTAL_FVOLUME', 'TOTAL_BPACKETS', 'TOTAL_BVOLUME',
    'MIN_FPKTL', 'MEAN_FPKTL', 'MAX_FPKTL', 'STD_FPKTL',
    'MIN_BPKTL', 'MEAN_BPKTL', 'MAX_BPKTL', 'STD_BPKTL',
    'MIN_FIAT', 'MEAN_FIAT', 'MAX_FIAT', 'STD_FIAT',
    'MIN_BIAT', 'MEAN_BIAT', 'MAX_BIAT', 'STD_BIAT',
    'DURATION',
    'MIN_ACTIVE', 'MEAN_ACTIVE', 'MAX_ACTIVE', 'STD_ACTIVE',
    'MIN_IDLE', 'MEAN_IDLE', 'MAX_IDLE', 'STD_IDLE',
    'SFLOW_FPACKETS', 'SFLOW_FBYTES', 'SFLOW_BPACKETS', 'SFLOW_BBYTES',
    'FPSH_CNT', 'BPSH_CNT', 'FURG_CNT', 'BURG_CNT',
    'TOTAL_FHLEN', 'TOTAL_BHLEN',
    'DSCP', 'FIRSTTIME', 'FLAST', 'BLAST'
]
FEATURE_NAMES = [
    'TOTAL_FPACKETS', 'TOTAL_FVOLUME', 'TOTAL_BPACKETS', 'TOTAL_BVOLUME',
    'FPKTL', 'BPKTL', 'FIAT', 'BIAT',
    'DURATION',
    'ACTIVE', 'IDLE',
    'SFLOW_FPACKETS', 'SFLOW_FBYTES', 'SFLOW_BPACKETS', 'SFLOW_BBYTES',
    'FPSH_CNT', 'BPSH_CNT', 'FURG_CNT', 'BURG_CNT',
    'TOTAL_FHLEN', 'TOTAL_BHLEN',
    'DSCP', 'FIRSTTIME', 'FLAST', 'BLAST'
]
DISTRIBUTION_FEATURES = ['FPKTL', 'BPKTL', 'FIAT', 'BIAT', 'ACTIVE', 'IDLE']

FEATURE_N = len(ALL_FEATURE_NAMES)

P_FORWARD = 0
P_BACKWARD = 1
FLOW_TIMEOUT = 600000000
IDLE_THRESHOLD = 1000000


class ValueFeature():
    def __init__(self, init_val=0):
        self.value = init_val

    def add(self, value):
        self.value += value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class DistributionFeature():
    def __init__(self):
        self.sum = float(0)
        self.sumsq = float(0)
        self.count = 0
        self.min = float(0)
        self.max = float(0)

        self.mean = float(0)
        self.std  = float(0)

    def add(self, value):
        self.sum += value
        self.sumsq += value*value
        self.count += 1
        if value < self.min or self.min == 0:
            self.min = value
        if value > self.max or self.max == 0:
            self.max = value

        self.mean = self.sum / self.count
        self.std  = self.stddev(self.sumsq, self.sum, self.count)

    def stddev(self, sumsq, suma, count):
        if count < 2:
            return 0
        return sqrt((sumsq - (suma * suma / count)) / (count - 1))


flows = 0

class FlowData:
    def __init__(self, ippacket= None, tcppacket= None):
        global flows
        if ippacket:
            flows += 1
            log.debug('Creating Flow {} Data for ip: {}'.format(flows, str(ippacket.srcip)))
            self.src_ip = ippacket.srcip
            self.src_port = tcppacket.srcport
            self.dst_ip = ippacket.dstip
            self.dst_port = tcppacket.dstport
            self.proto = 'tcp'

            self.feat = {}
            self.initFeatures()

            feat = self.feat
            feat['DSCP'].set(getIPv4DSCP(ippacket))
            feat['TOTAL_FPACKETS'].set(1)
            length = ippacket.iplen
            feat['TOTAL_FVOLUME'].set(length)
            feat['FPKTL'].add(length)
            feat['FIRSTTIME'].set(int(time.time()))
            feat['FLAST'].set(feat['FIRSTTIME'].get())
            feat['TOTAL_FHLEN'].set(getIPV4HLen(ippacket) + tcppacket.hdr_len)
            self.activeStart = feat['FIRSTTIME'].get()

            self.cstate = TCPState()
            self.sstate = TCPState()
            if self.proto == 'tcp':
                self.cstate.state = TCPState.TCP_STATE_START
                self.sstate.state = TCPState.TCP_STATE_START

            self.valid = True
            self.hasData = False
            self.pdir = P_FORWARD
            self.updateStatus(ippacket, tcppacket)

    def initFeatures(self):
        for fname in FEATURE_NAMES:
            if fname in DISTRIBUTION_FEATURES:
                self.feat[fname] = DistributionFeature()
            else:
                self.feat[fname] = ValueFeature()

    def getLastTime(self):
        flast = self.feat['FLAST'].get()
        blast = self.feat['BLAST'].get()

        if blast == 0:
            return flast
        if flast == 0:
            return blast
        if flast > blast:
            return flast

        return blast
    
    def updateTCPState(self, tcppkt):
        #log.debug('UPDATING TCP STATE!')
        self.cstate.tcpUpdate(tcppkt, P_FORWARD, self.pdir)
        self.cstate.tcpUpdate(tcppkt, P_BACKWARD, self.pdir)

    def updateStatus(self, ippkt, tcppkt= None):
        if self.proto == 'udp':
            if self.valid:
                return
            if ippkt.iplen > 8:
                self.hasData = True
            if self.hasData and self.isBidir:
                self.valid = True
        elif self.proto == 'tcp':
            headers_len = getIPV4HLen(ippkt) + tcppkt.hdr_len
            if not self.valid:
                if self.cstate.state == TCPState.TCP_STATE_ESTABLISHED:
                    if ippkt.iplen > headers_len:
                        self.valid = True
            self.updateTCPState(tcppkt)

    def add(self, ippkt, tcppkt):
        src_ip = ippkt.srcip
        now = int(time.time())
        last = self.getLastTime()

        diff = now - last

        if diff > FLOW_TIMEOUT:
            # Timetout ADD IDLE
            return
        if now < last:
            print('FATAL: Packet at less time than previous ones')
            return
        
        length = ippkt.iplen
        hlen = getIPV4HLen(ippkt) + tcppkt.hdr_len # IP Header Len + TCP Header Len

        if src_ip == self.src_ip:
            self.pdir = P_FORWARD
        else:
            self.pdir = P_BACKWARD

        feat = self.feat
        
        if diff > IDLE_THRESHOLD:
            feat['IDLE'].add(diff)

            diff = last - self.activeStart
            feat['ACTIVE'].add(diff)

            feat['FLAST'].set(0)
            feat['BLAST'].set(0)
            self.activeStart = now
        

        # Calculate Statistics
        feat['DURATION'].set(last - feat['FIRSTTIME'].get())
        if self.pdir == P_FORWARD:
            # Forwards
            feat['FPKTL'].add(length)
            feat['TOTAL_FVOLUME'].add(length)
            feat['TOTAL_FPACKETS'].add(1)
            feat['TOTAL_FHLEN'].add(hlen)

            if feat['FLAST'].get() > 0:
                diff = now - feat['FLAST'].get()
                feat['FIAT'].add(diff)

            if self.proto == 'tcp':
                if tcppkt.PSH:
                    feat['FPSH_CNT'].add(1)
                if tcppkt.URG:
                    feat['FURG_CNT'].add(1)
            
            feat['FLAST'].set(now)
        
        else:
            # Backwards
            self.isBidir = True

            feat['BPKTL'].add(length)
            feat['TOTAL_BVOLUME'].add(length)
            feat['TOTAL_BPACKETS'].add(1)
            feat['TOTAL_BHLEN'].add(hlen)

            if feat['BLAST'].get() > 0:
                diff = now - feat['BLAST'].get()
                feat['BIAT'].add(diff)

            feat['BLAST'].set(now)

        if feat['DSCP'].get() == 0:
            feat['DSCP'].set(getIPv4DSCP(ippkt))

        if self.proto == 'tcp':
                if tcppkt.PSH:
                    feat['FPSH_CNT'].add(1)
                if tcppkt.URG:
                    feat['FURG_CNT'].add(1)

        # Update Connection Status
        self.updateStatus(ippkt, tcppkt)



    def isClosed(self):
        return self.cstate.state == TCPState.TCP_STATE_CLOSED and self.sstate.state == TCPState.TCP_STATE_CLOSED

    def toJsonDict(self):
        data = {}
        for fname in FEATURE_NAMES:
            if fname in DISTRIBUTION_FEATURES:
                dfeat = self.feat[fname]
                data['MIN_{}'.format(fname)] = dfeat.min
                data['MEAN_{}'.format(fname)] = dfeat.mean
                data['MAX_{}'.format(fname)] = dfeat.max
                data['STD_{}'.format(fname)] = dfeat.std
            else:
                data[fname] = self.feat[fname].get()
        
        return data


class FlowKey:
    def __init__(self, ippacket, tcppacket):
        ip1 = str(ippacket.srcip)
        port1 = tcppacket.srcport
        ip2 = str(ippacket.dstip)
        port2 = tcppacket.dstport

        if ip1 > ip2:
            self.key = "{},{},{},{},tcp".format(ip1, port1, ip2, port2)
        else:
            self.key = "{},{},{},{},tcp".format(ip2, port2, ip1, port1)
    
    def __eq__(self, o):
        if not isinstance(o, FlowKey):
            return False
        if self.key != o.key:
            return False
        return True
    
    def __hash__(self):
        return hash(self.key)

    def __str__(self):
        return self.key


ids_queue = Queue()
flows_map = {}

def packet_handler(event):
    core.getLogger('ips_controller').debug('Packet detected!')
    packet = event.parse()
    ippacket = packet.find(ipv4)
    tcppacket = packet.find(tcp)

    if ippacket and tcppacket:
        fkey = FlowKey(ippacket, tcppacket)
        if fkey not in flows_map:
            f = FlowData(ippacket, tcppacket)
            flows_map[fkey] = f
        else:
            f = flows_map[fkey]
            f.add(ippacket, tcppacket)

        ids_queue.put((fkey, f.toJsonDict()))

        #if f.isClosed():
            #flows_map.pop(fkey, None)

def ids_job():
    # core.getLogger('ips_controller').debug('Checking for flows to process...')
    if not ids_queue.empty():
        n = ids_queue.qsize()
        while n > 0:
            n -= 1
            fkey, fdata = ids_queue.get()
            print("Going to check flow: {}...".format(str(fkey)))           
            log = core.getLogger('ips_controller')
            srcport = str(fkey).split(',')[1]
            
            log.debug('Packet port: '+srcport)
            # log.debug('DURATION: ' + str(fdata['DURATION']))
            log.debug(str(fdata))
            resp = r.post('http://192.168.1.68:80', json=fdata)

            resp = resp.json()
            prob = float(resp['prediction'][0][0])
            core.getLogger('ips_controller').debug('Returned Prob: '+str(prob))
            if prob > 0.5:
                core.getLogger('ips_controller').debug('We are being attacked!!!!!!')
            # Check if flow data as it is, is malicious
            # classify(fdata)



def launch(ports=''):
    global log
    log = core.getLogger('ips_controller')
    log.debug('Setting up ids controller') 
    core.openflow.addListenerByName("PacketIn", packet_handler)
    # Start Classifier Job
    Timer(3, ids_job, recurring=True)
