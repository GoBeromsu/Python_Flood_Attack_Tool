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
    else:
        print("Attack Type is Missing")
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
    

# def set

main()
