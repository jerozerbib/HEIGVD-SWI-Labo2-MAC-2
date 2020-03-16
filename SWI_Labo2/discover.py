#!/usr/bin/env python3
from scapy.all import *
import argparse
import os

parser = argparse.ArgumentParser()

parser.add_argument("--ssid", required=True, type=str, help="SSID to look up")
parser.add_argument("--interface", default="wlan0mon", help="Interface to use")



args = parser.parse_args()

STAs = []
searched_ssid = args.ssid
iface = args.interface

def pkt_callback(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        print(pkt.info.decode())
        bss = pkt.getlayer(Dot11Elt)
        if pkt.info.decode() == searched_ssid:
            print("trouvé \n")
            print(pkt.addr2)
            if pkt.addr2 not in STAs:
                STAs.append(pkt.addr2)



if __name__ == "__main__":
    print (searched_ssid)
    for it in range (1,14):
        cmd = "iwconfig wlan0mon channel " + str(it)
        os.system(cmd)
        sniff(iface="wlan0mon", prn=pkt_callback, timeout=4)
    print(STAs)
