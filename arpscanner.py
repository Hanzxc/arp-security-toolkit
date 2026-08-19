#!/usr/bin/env python3
"""
arpscanner.py  -  Real-time ARP spoofing detector
CSCI369 Ethical Hacking

WHAT IT DOES
    Passively sniffs live ARP traffic and flags ARP spoofing by watching for
    IP-to-MAC conflicts: i.e. one IP address suddenly being claimed by a
    different MAC address than we saw before. That is exactly the footprint an
    ARP spoofer leaves when it forges replies to remap the gateway IP to the
    attacker's MAC (see Question 1).

    Runs completely independently of arp_spoofer.py:
        sudo python arpscanner.py

REQUIREMENTS
    pip install scapy
    Run with root/admin (raw packet capture needs elevated privileges).

HOW TO DEMO
    1. In one terminal:  sudo python arpscanner.py
    2. In another VM:    run arp_spoofer.py against a target.
    The scanner should print a red-flag alert the moment the forged replies
    start rewriting an IP's MAC.
"""

import sys
from datetime import datetime

from scapy.all import sniff, ARP, conf


def print_author_banner():
    """Print the author and the current date (formatted with strftime)."""
    # Define variables
    author = "Ong Jun Han"
    current_date = datetime.now().strftime("%d/%m/%Y")

    # Display the output
    print(f"Author: {author}")
    print(f"Date: {current_date}")

# Remembers the MAC we have currently associated with each IP.
#   key   = IP address (string)
#   value = MAC address (string)
ip_mac_table = {}


def get_active_interface():
    """
    Auto-identify the active interface instead of hardcoding 'eth0'.

    Scapy resolves the interface tied to the default route into conf.iface,
    so we reuse that. Returns the interface name as a string.
    """
    iface = conf.iface
    return str(iface)


def process_packet(packet):
    """
    Callback run by sniff() for every captured ARP frame.

    We only care about ARP *replies* (op == 2, "is-at"), because that is the
    message a spoofer forges. For each reply we compare the claimed MAC against
    what we already have on record for that IP.
    """
    # Safety check: make sure this really is an ARP layer.
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    # op codes:  1 = who-has (request)   2 = is-at (reply)
    # Spoofing is carried by forged replies, so we inspect op == 2.
    if arp.op != 2:
        return

    ip = arp.psrc      # the IP address being advertised
    mac = arp.hwsrc    # the MAC claiming to own that IP

    if ip in ip_mac_table:
        known_mac = ip_mac_table[ip]

        if known_mac != mac:
            # CONFLICT: same IP, different MAC than before -> likely spoofing.
            print("\n[!!!] POSSIBLE ARP SPOOFING DETECTED")
            print(f"      IP address : {ip}")
            print(f"      was at MAC : {known_mac}   (previously seen)")
            print(f"      now at MAC : {mac}   (new claim)")
            print("      -> An IP-to-MAC conflict like this is the signature "
                  "of a forged ARP reply.\n")

            # Update to the newest claim so we can catch further flip-flops
            # (spoofers often flap the mapping repeatedly).
            ip_mac_table[ip] = mac
        # else: same IP, same MAC -> normal, nothing to do.
    else:
        # First time we've seen this IP. Record it as the baseline.
        ip_mac_table[ip] = mac
        print(f"[+] Learned  {ip}  ->  {mac}")


def main():
    print_author_banner()
    print()

    iface = get_active_interface()
    print(f"[*] Active interface auto-detected: {iface}")
    print("[*] Sniffing ARP traffic only (BPF filter: 'arp')...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        # filter="arp"  -> BPF-level filter so ONLY ARP frames are captured,
        #                  keeping the amount of captured traffic minimal.
        # prn           -> our per-packet callback above.
        # store=0       -> don't keep packets in memory (we handle them live).
        sniff(iface=iface, filter="arp", prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user. Exiting.")
        sys.exit(0)
    except PermissionError:
        sys.exit("[!] Permission denied. Run with sudo.")


if __name__ == "__main__":
    main()
