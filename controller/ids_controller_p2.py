"""
Cortafuegos-Diable: POX Controller
Author: Doritos Electronicos
Descripcion: Un script aplicacion POX que intercepta paquetes para calcular estadisticas flowbag y enviarlas periodicamente a un API de clasificacion.
"""

from Queue import Queue
from math import sqrt
import time
import threading

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.recoco import Timer

import requests as r

# Configurations parameters Default in launch function
API_SERVICE_IP = ''
API_SERVICE_PORT = 0
PERIODIC_JOB_SECONDS = 0

## Corrections to POX
# POX IPv4 unpacking TOS is wrong. TOS is 6 bits and IPv4 stores the full byte
# We remove the 2 extra bits that are ECN (2 bits) field
def getIPv4DSCP(ippkt):
    return ippkt.tos >> 2

# POX IPv4 Header Length is units of 32-bit WORDS, we need to mulitply by 4 to get bytes
# POX TCP  Header Length is already given in bytes, so need to multiply
def getIPv4HLen(ippkt):
    return ippkt.hl * 4

# Global Variables
StopApp = False
log = {}

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


total_flows_created = 0

class FlowData:
    def __init__(self, ippacket= None, tcppacket= None):
        global total_flows_created
        total_flows_created += 1
        log.debug('Creating Flow {} Data for ip: {}'.format(total_flows_created, str(ippacket.srcip)))
        
        self.src_ip = ippacket.srcip
        self.src_port = tcppacket.srcport
        self.dst_ip = ippacket.dstip
        self.dst_port = tcppacket.dstport
        self.proto = 'tcp'

        self.pdir = P_FORWARD
        self.valid = False
        self.hasData = False
        self.isBidir = False

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
        feat['TOTAL_FHLEN'].set(getIPv4HLen(ippacket) + tcppacket.hdr_len)
        self.activeStart = feat['FIRSTTIME'].get()

        self.cstate = TCPState()
        self.sstate = TCPState()
        if self.proto == 'tcp':
            self.cstate.state = TCPState.TCP_STATE_START
            self.sstate.state = TCPState.TCP_STATE_START

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
        self.cstate.tcpUpdate(tcppkt, P_FORWARD, self.pdir)
        self.sstate.tcpUpdate(tcppkt, P_BACKWARD, self.pdir)

    def updateStatus(self, ippkt, tcppkt= None):
        if self.proto == 'udp':
            if self.valid:
                return
            if ippkt.iplen > 8:
                self.hasData = True
            if self.hasData and self.isBidir:
                self.valid = True
        elif self.proto == 'tcp':
            headers_len = getIPv4HLen(ippkt) + tcppkt.hdr_len
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
        hlen = getIPv4HLen(ippkt) + tcppkt.hdr_len # IP Header Len + TCP Header Len

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
            lowercase_fname = fname.lower()
            if fname in DISTRIBUTION_FEATURES:
                dfeat = self.feat[fname]
                data['min_{}'.format(lowercase_fname)] = dfeat.min
                data['mean_{}'.format(lowercase_fname)] = dfeat.mean
                data['max_{}'.format(lowercase_fname)] = dfeat.max
                data['std_{}'.format(lowercase_fname)] = dfeat.std
            else:
                data[lowercase_fname] = self.feat[fname].get()
        
        return data


class FlowKey:
    def __init__(self, ippacket, tcppacket, proto):
        ip1 = str(ippacket.srcip)
        port1 = tcppacket.srcport
        ip2 = str(ippacket.dstip)
        port2 = tcppacket.dstport

        if ip1 > ip2:
            self.key = "{},{},{},{},{}".format(ip1, port1, ip2, port2, proto)
        else:
            self.key = "{},{},{},{},{}".format(ip2, port2, ip1, port1, proto)
    
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
    log.debug('Packet In Detected!')
    packet = event.parse()
    ippacket = packet.find(ipv4)
    tcppacket = packet.find(tcp)
    
    if ippacket and tcppacket:
        log.debug('From {} -> {}'.format(str(ippacket.srcip), str(ippacket.dstip)))
        fkey = FlowKey(ippacket, tcppacket, 'tcp')
        if fkey not in flows_map:
            f = FlowData(ippacket, tcppacket)
            flows_map[fkey] = f
        else:
            f = flows_map[fkey]
            f.add(ippacket, tcppacket)

        ids_queue.put((fkey, f.toJsonDict()))

        if f.isClosed():
            # Removing flow from table if connection is closed!
            flows_map.pop(fkey, None)
            log.debug('Connection {} was closed!'.format(str(fkey)))

def ids_job(thread_name='ids_job'):
    def th_print(s):
        log.debug('{}:{}'.format(thread_name, s))

    while (True):
        if StopApp:
            break
        time.sleep(PERIODIC_JOB_SECONDS)
        if not ids_queue.empty():
            n = ids_queue.qsize()
            while n > 0:
                # Check if flow data as it is, is malicious
                # classify(fdata)
                n -= 1
                fkey, fdata = ids_queue.get()
                th_print("Going to evaluate flow: {}...".format(str(fkey)))
                th_print('FlowData:')
                th_print(str(fdata))

                th_print('Sending to API service...')
                api_url = "http://{}:{}".format(API_SERVICE_IP, str(API_SERVICE_PORT))
                resp = r.post(api_url, json=fdata)

                resp = resp.json()
                attack_prob = float(resp['prediction'][0][0])
                th_print('Returned Attack p(x): {}'.format(str(attack_prob)))
                if attack_prob > 0.5:
                    th_print('WE ARE UNDER ATTACK!!!!!!')

def shutdown_handler(event):
    log.debug('Shutting down...')
    global StopApp
    StopApp = True

def launch(apiip='127.0.0.1', apiport=5000, jobseconds=3):
    global log
    log = core.getLogger('ids_controller')
    log.debug('Setting up ids_controller...') 

    global API_SERVICE_IP
    global API_SERVICE_PORT
    global PERIODIC_JOB_SECONDS
    API_SERVICE_IP = str(apiip)
    API_SERVICE_PORT = int(apiport)
    PERIODIC_JOB_SECONDS = int(jobseconds)

    core.openflow.addListenerByName("PacketIn", packet_handler)
    core.addListenerByName("GoingDownEvent", shutdown_handler)
    # Start Classifier Job
    
    # POX RECOCO Threads are cooperative and if one blocks, all block
    #Timer(PERIODIC_JOB_SECONDS, ids_job, recurring=True)
    ids_eval_job = threading.Thread(target=ids_job, args=("ids_job",))
    ids_eval_job.start()
