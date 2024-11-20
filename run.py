from netfilterqueue import NetfilterQueue
from scapy.all import *
import socket
import enum
import sys
import os

class DnsRule:
    def __init__(self, rtype, dtype, target, val):
        assert(rtype in ["ACCEPT", "DENY"])
        assert(dtype in ["DNSQR", "DNSRR"])
        self.rtype = rtype
        self.dtype = dtype
        self.target = target
        self.val = val
        
    def check(self, pkt):
        if pkt.haslayer(self.dtype):
            dns_data = pkt[self.dtype]
        else:
            return True

        if self.dtype == "DNSRR":
            assert(self.target in ["rrname", "type", "rdata"])
            if self.target == "type":
                assert(isinstance(self.target, int))
        else:
            assert(self.target in ["qname", "qtype"])
            if self.target == "qtype":
                assert(isinstance(self.target, int))

        target_val = eval(f"dns_data.{self.target}").decode('ascii')
        res = (target_val == self.val)
        if self.rtype == "DENY":
            res = not res
        return res

def read_config(filename):
    rules = []

    with open(filename, "r") as inp:
        lines = inp.readlines()

    for line in lines:
        rule = line.strip().split()
        rules.append(DnsRule(*rule))

    return rules

def main():
    rules = read_config(sys.argv[1])
    queue_num = int(sys.argv[2])
    def callback(pkt):
        data = pkt.get_payload()
        scppkt = IP(data)
        if scppkt.haslayer(DNS):
            if all(rule.check(scppkt) for rule in rules):
                pkt.accept()
            else:
                pkt.drop()
        else:
            pkt.accept()

    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, callback)
    sock = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        nfqueue.run_socket(sock)
    except KeyboardInterrupt:
        pass

    sock.close()
    nfqueue.unbind()

if __name__ == '__main__':
    main()

