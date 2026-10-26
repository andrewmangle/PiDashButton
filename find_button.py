#!/usr/bin/env python3
"""
Find your Dash button's MAC address.

Run with sudo, then press the Dash button. Devices that send DHCP or ARP
broadcasts are printed. The address that shows up right after each press
is your button. It should match the MAC shown on the button's setup page
at http://192.168.0.1, and its vendor prefix belongs to Amazon Technologies Inc.

    sudo python3 find_button.py
"""

from scapy.all import DHCP, Ether, sniff

seen = set()


def show(pkt):
    if not pkt.haslayer(Ether):
        return
    mac = pkt[Ether].src.lower()
    kind = "DHCP" if pkt.haslayer(DHCP) else "ARP "
    tag = "NEW " if mac not in seen else "    "
    seen.add(mac)
    print(f"{tag}{kind}  {mac}", flush=True)


print("Listening... press your Dash button now. Ctrl+C to stop.", flush=True)
sniff(filter="arp or (udp and (port 67 or port 68))", prn=show, store=False)
