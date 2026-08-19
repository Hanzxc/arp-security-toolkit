# ARP Security Toolkit

> An attack-and-defense pair of Python tools built with [Scapy](https://scapy.net/):
> an **ARP cache-poisoning man-in-the-middle** attacker and a **real-time ARP-spoofing
> detector** that catches it.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Scapy](https://img.shields.io/badge/built%20with-Scapy-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

> [!WARNING]
> **For education and authorized testing only.** These tools send forged ARP
> frames on a network. Only run them on a lab network you own or have **explicit
> written permission** to test. Unauthorized ARP spoofing is illegal in most
> jurisdictions. See the [disclaimer](#disclaimer).

---

## Overview

On a local network, hosts reach each other by **MAC address**, and ARP (Address
Resolution Protocol) is the lookup that maps an IP address to the MAC that owns
it. ARP has no authentication — a host will cache any reply it receives, even one
it never asked for and even one that is a lie. This repository demonstrates both
sides of that weakness:

| Tool | Role | What it does |
|------|------|--------------|
| [`arpspoof.py`](arpspoof.py)   | 🔴 Attack  | Poisons the ARP tables of a victim and its gateway so all their traffic flows through the attacker (a man-in-the-middle). |
| [`arpscanner.py`](arpscanner.py) | 🔵 Defense | Passively sniffs ARP traffic and raises an alert the instant an IP's MAC address changes — the signature of a spoofing attack. |

Together they tell a complete story: how the attack works, and how a defender
detects it.

---

## How it works

### The attack — `arpspoof.py`

The spoofer continuously sends forged ARP **replies** (`op=2`, "is-at"):

- To the **victim** it says: *"the gateway is at MY MAC address."*
- To the **gateway** it says: *"the victim is at MY MAC address."*

Both sides believe the lie and send their frames to the attacker instead of to
each other. With IP forwarding enabled, the attacker relays the traffic so the
connection keeps working while sitting invisibly in the middle. On `Ctrl+C`, the
tool sends the **correct** mappings back to both hosts, leaving the network clean.

```
        Before                                 During the attack
  ┌────────┐   ┌────────┐              ┌────────┐   ┌──────────┐   ┌────────┐
  │ Victim │──▶│ Gateway│              │ Victim │──▶│ Attacker │──▶│ Gateway│
  └────────┘   └────────┘              └────────┘◀──│  (MITM)  │◀──└────────┘
                                                    └──────────┘
```

### The defense — `arpscanner.py`

On a healthy network an IP maps to a single, stable MAC. The scanner keeps a
table of every `IP → MAC` mapping it has seen. When an IP that it already knows
is suddenly claimed by a **different** MAC, that conflict is flagged as possible
spoofing. It is fully passive — it only listens and never sends a packet.

---

## Requirements

- **Python 3.10+**
- **Scapy** — `pip install scapy`
- **Linux** (e.g. Kali) with **root privileges** — raw packet crafting and
  capture need elevated permissions.

```bash
pip install -r requirements.txt
```

---

## Usage

### Run the detector (defender machine)

```bash
sudo python3 arpscanner.py
```

It auto-detects the active interface, applies a kernel-level BPF filter so only
ARP frames are captured, and prints activity live. Press `Ctrl+C` to stop.

### Run the attacker (attacker machine)

First enable IP forwarding, or the victim will lose connectivity and the attack
becomes obvious:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Then run the spoofer with the victim and gateway IPs:

```bash
sudo python3 arpspoof.py <Victim_IP> <Gateway_IP>
# example:
sudo python3 arpspoof.py 192.168.1.20 192.168.1.1
```

Press `Ctrl+C` to stop and automatically restore both ARP tables.

**Optional flags:**

| Flag | Description |
|------|-------------|
| `-i`, `--iface ETH` | Network interface to use (e.g. `eth0`). Defaults to Scapy's choice. |
| `--interval N`      | Seconds between re-poisoning bursts (default `2`). A short interval keeps the poisoned entries fresh. |

### See them work together

1. On the defender: `sudo python3 arpscanner.py`
2. On the attacker: `sudo python3 arpspoof.py <Victim_IP> <Gateway_IP>`

The scanner prints a red-flag alert the moment the forged replies start
rewriting an IP's MAC.

---

## Example output

**Attacker:**
```
Author: Ong Jun Han
Date: 17/08/2026

[*] Resolving MAC addresses...
    target  192.168.1.20  -> aa:bb:cc:dd:ee:ff
    gateway 192.168.1.1   -> 11:22:33:44:55:66

[*] Poisoning... press Ctrl+C to stop and restore.

[+] Packets sent: 42
```

**Detector:**
```
[+] Learned  192.168.1.1  ->  11:22:33:44:55:66

[!!!] POSSIBLE ARP SPOOFING DETECTED
      IP address : 192.168.1.1
      was at MAC : 11:22:33:44:55:66   (previously seen)
      now at MAC : de:ad:be:ef:00:01   (new claim)
      -> An IP-to-MAC conflict like this is the signature of a forged ARP reply.
```

---

## Notes and limitations

- If IP forwarding is off, the victim loses its connection during the attack,
  which makes it obvious. Enable it first.
- The detector flags spoofing by a **change** in mapping, so it must see the
  genuine mapping first to have a baseline. It reports that a conflict exists but
  cannot by itself say which MAC is the attacker — confirm against known-good
  values (e.g. the router's real MAC).
- A legitimate change (a replaced device, a failover) can also trigger an alert.
  Treat an alert as a prompt to investigate, not as absolute proof.

---

## Disclaimer

This project was written for the **CSCI369 Ethical Hacking** course as an
educational demonstration of ARP-layer attacks and defenses. It is provided for
learning and for **authorized** security testing only. The author accepts no
liability for misuse. Do not run these tools against any network you do not own
or lack explicit permission to test.

## Author

**Ong Jun Han** — CSCI369 Ethical Hacking

## License

Released under the [MIT License](LICENSE).
