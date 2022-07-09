from sys import stdout
from scapy.all import *
from random import randint
from argparse import ArgumentParser


# ICMP/UDP/TCP Flood Attack Tool
def main():
    parser = ArgumentParser()
    parser.add_argument("--type", "-T", help="attack number of repetition")
    parser.add_argument("--target", "-t", help="target IP address")
    parser.add_argument("--port", "-p", help="target port number")
    parser.add_argument("--repeat", "-r", help="attack number of repetition")

    args = parser.parse_args()
    if args.type:
        pass
    if args.target:
        pass
    if args.port:
        pass
    if args.repeat:
        pass

main()
