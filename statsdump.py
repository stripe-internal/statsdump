#!/usr/bin/env python
import dpkt
import sys
import socket
from collections import defaultdict
from operator import itemgetter


def parse_ip4_packet(buf):
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        raise Exception('unhandled type: %s' % eth.type)
    
    ip = eth.data
    if ip.p not in [dpkt.ip.IP_PROTO_UDP, dpkt.ip.IP_PROTO_TCP]:
        raise Exception('unhandled protocol: %s' % ip.p)
    

    packet_data = ip.data
    return socket.inet_ntoa(ip.src), ip.p == dpkt.ip.IP_PROTO_UDP, packet_data.data



def pcap_buffers(stream):
    for ts, buf in dpkt.pcap.Reader(stream):
        yield buf


def parse_statsd(data):
    kv, metrictype = data.split('|')[:2]
    if ':' not in kv:
        return kv, metrictype
    return kv.split(':')[0], metrictype


def hot(d, n):
    return list(reversed(sorted(d.items(), key=itemgetter(1))))[:n]


def print_table(name, d, n, total, cdf=True):
    print 'Hot %s:' % name
    print '---------------'

    cs = 0.
    for thing, count in hot(d, n):
        cs += count
        print '%d\t%.2f\t%s\t%s' % (
            count,
            float(count) / total,
            '%.2f' % (cs / total) if cdf else '-',
            thing
        )

    print


def main():
    hosts = defaultdict(int)
    keys = defaultdict(int)
    prefixes = defaultdict(int)

    total, total_udp, total_tcp = 0,0,0
    error_skipped = 0
    data = ""
    for buf in pcap_buffers(sys.stdin):
        try:
            ip, is_udp, this_data = parse_ip4_packet(buf)
            data += this_data
        except dpkt.dpkt.NeedData:
            continue
       
        try:
            key, metrictype = parse_statsd(data)
            hosts[ip] += 1
            keys[key] += 1

            parts = key.split('.')
            for prefix in ['.'.join(parts[:n]) for n in range(1, len(parts)+1)]:
                prefixes[prefix] += 1

            total += 1
            if is_udp: total_udp +=1
            else: total_tcp +=1
            data = ''
        except:
            error_skipped +=1

    print("Skipped {}/{} packets. {} UDP packets, {} TCP packets.".format(error_skipped, total, total_udp, total_tcp))
    print_table('hosts', hosts, 20, total)
    print_table('keys', keys, 20, total)
    print_table('prefixes', prefixes, 20, total, False)

    
if __name__ == '__main__':
    main()

        




