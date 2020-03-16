# Source : https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/

import argparse

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, Dot11ProbeResp

parser = argparse.ArgumentParser()

parser.add_argument("--interface", required=True, help="Interface to use")

args = parser.parse_args()
interface = args.interface


# Permet de scanner tous les canaux en background
# On met chaque scan de canal dans un Thread dans le "main"
def hopper(interf):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (interf, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig


F_bssids = []  # Found BSSIDs


def findSSID(pkt):
    # Nous voulons etre sur que la fonction aie la couche Beacon.
    # Si c'est le cas, on peut garantir que le paquet vient d'une AP
    if pkt.haslayer(Dot11Beacon):
        # Nous verifions que l'adresse MAC d'une AP n'a pas deja ete detecte
        if pkt.getlayer(Dot11).addr3 not in F_bssids:
            F_bssids.append(pkt.getlayer(Dot11).addr3)
    elif pkt.haslayer(Dot11ProbeResp) and pkt.addr3 in F_bssids:
                print("Hidden Network Detected : " + pkt.info.decode())


if __name__ == "__main__":
    thread = threading.Thread(target=hopper, args=(interface,), name="hopper")
    thread.daemon = True
    thread.start()

    sniff(iface=interface, prn=findSSID)
