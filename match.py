#!/usr/bin/env python3
from scapy.all import *
import argparse
import os

parser = argparse.ArgumentParser()

#parser.add_argument("--ssid", required=True, type=str, help="SSID to look up")
parser.add_argument("--interface", default="wlan0mon", help="Interface to use")



args = parser.parse_args()
iface = args.interface
AP_with_STA = {};


def matching_addr(sta, ap):
    if sta not in AP_with_STA:
        AP_with_STA[sta] = []
    if ap not in AP_with_STA[sta] and ap != sta:
        AP_with_STA.setdefault(sta, []).append(ap)

def pkt_callback_bis(pkt):
    if pkt.haslayer(Dot11Elt) and pkt.type == 2: #Data frames
        print("Dataframe recieved")
        pkt.show()
        DS = pkt.FCfield & 0x3
        toDS = DS & 0x01 != 0
        fromDS = DS & 0x2 != 0
        if toDS and not fromDS:
            """
            Address 1 = BSSID
            Address 2 = Source
            Address 3 = Destination
            """
            matching_addr(pkt.addr1, pkt.addr3)

        elif not toDS and fromDS:
            """
            Address 1 = Destination
            Address 2 = BSSID
            Address 3 = Source
            """
            matching_addr(pkt.addr2, pkt.addr1)


        elif not toDS and not fromDS  :

            """
            Address 1 = Destination
            Address 2 = Source
            Address 3 = BSSID
            """
            matching_addr(pkt.addr3, pkt.addr2)
            matching_addr(pkt.addr3, pkt.addr1)

if __name__ == "__main__":


    for it in range (1,14):
        cmd = "iwconfig wlan0mon channel " + str(it)
        os.system(cmd)
        sniff(iface="wlan0mon", prn=pkt_callback_bis, timeout=10)

    for MAC in AP_with_STA:
        print(MAC + " connected to ", AP_with_STA[MAC])
