from netfilterqueue import NetfilterQueue
from scapy.all import *
import argparse
import socket
import enum
import sys
import os

class Answer(enum.Enum):
    accept = 0
    drop = 1
    skip = 2

class DnsRule:
    def __init__(self, rtype, dtype, target, val):
        assert(rtype in ["ACCEPT", "DENY"])
        assert(dtype in ["DNSQR", "DNSRR"])
        self.rtype = rtype
        self.dtype = dtype
        self.target = target
        self.val = val
        
    def check(self, pkt):
        print("[CHECK_RULE]", self.rtype, self.dtype, self.target, self.val)

        if self.dtype == "DNSRR":
            assert(self.target in ["rrname", "type", "rdata"])
        else:
            assert(self.target in ["qname", "qtype"])

        if not pkt.haslayer(self.dtype):
            return Answer.skip

        dns_data = pkt[self.dtype]
        target_val = eval(f"dns_data.{self.target}")
        if self.target not in ["type", "qtype"]:
            target_val = target_val.decode('ascii')
        else:
            assert(self.val.isdigit())
            target_val = str(target_val)
        res = (target_val == self.val)
        if res:
            if self.rtype == "ACCEPT":
                return Answer.accept
            return Answer.drop
        return Answer.skip

def read_config(filename):
    rules = []

    with open(filename, "r") as inp:
        lines = inp.readlines()

    for line in lines:
        rule = line.strip().split()
        rules.append(DnsRule(*rule))

    return rules

def main():
    parser = argparse.ArgumentParser(prog='nfqueue-filter')
    parser.add_argument('config')
    parser.add_argument('--queue-num', type=int, default=1)
    parser.add_argument('--default-action', default="accept")
    args = parser.parse_args()

    rules = read_config(args.config)
    queue_num = int(args.queue_num)
    assert(args.default_action in ['accept', 'drop'])
    default_action = Answer.accept if args.default_action == 'accept' else Answer.drop

    def callback(pkt):
        data = pkt.get_payload()
        scppkt = IP(data)
        if not scppkt.haslayer(DNS):
            pkt.accept()
            return

        print("[DNS_DATA]", scppkt[DNS])

        flag = True
        ans = Answer.skip
        for rule in rules:
            ans = rule.check(scppkt)
            if ans == Answer.skip:
                continue
            else:
                flag = False
                break
        if flag:
            print("[DEFAULT]", end=' ')
            ans = default_action
        print("[ANS]", ans)
        if ans == Answer.accept:
            pkt.accept()
        else:
            pkt.drop()

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

