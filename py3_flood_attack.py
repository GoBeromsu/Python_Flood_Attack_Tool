from sys import stdout
from scapy.all import *
from random import randint
from argparse import ArgumentParser


# ICMP/UDP/TCP Flood Attack Tool
def main():
    parser = ArgumentParser()
    parser.add_argument("--SynFlood", "-s", help="Syn Flood Attack")
    parser.add_argument("--UDPFlood", "-u", help="UDP Flood Attack")
    parser.add_argument("--ICMPFlood", "i", help="ICMP Flood Attack")
    parser.add_argument("--target", "-t", required=True, help="target IP address")
    parser.add_argument("--port", "-p", default=80, help="target port number")
    parser.add_argument(
        "--repeat", "-r", default=100, help="attack number of repetition"
    )

    args = parser.parse_args()
    if args.target:
        print(args.target)
    else:
        print("Targert is Missing")
    if args.port:
        pass
    else:
        print("Current Port is 80")
    if args.repeat:
        pass
    
    if not SynFlood and not UDPFlood and not ICMPFlood:
        pass
    
def SynFlood():
    pass
def UDPFlood():
    pass
def ICMPFlood():
    pass
main()
