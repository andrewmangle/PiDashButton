#!/usr/bin/env python3
"""
Dash button listener for Raspberry Pi.

Each press of an Amazon Dash button wakes it up and makes it rejoin your
Wi-Fi, which sends DHCP and ARP broadcasts from the button's MAC address.
This script watches for those packets and runs an action on the Pi.

Run with sudo (packet sniffing needs root):
    sudo python3 dash_listener.py
"""

import csv
import datetime
import logging
import subprocess
import time
from pathlib import Path

from scapy.all import Ether, sniff

# ---------------------------------------------------------------------------
# SETTINGS: edit these
# ---------------------------------------------------------------------------

# Your button MAC address(es), lowercase, mapped to a friendly name.
BUTTONS = {
    "aa:bb:cc:dd:ee:ff": "Dash button 1",
    # "11:22:33:44:55:66": "Dash button 2",
}

# Network interface to listen on. None lets Scapy pick the default.
# Use "eth0" for wired or "wlan0" for Wi-Fi if you need to force it.
INTERFACE = None

# One press sends several packets over a few seconds; ignore repeats
# from the same button inside this window.
DEBOUNCE_SECONDS = 10

# GPIO pin (BCM numbering) for the LED. GPIO17 is physical pin 11.
LED_PIN = 17

# CSV log of every press, saved next to this script.
LOG_FILE = Path(__file__).with_name("presses.csv")

# Sound to play on a press. Set to None to disable.
SOUND_FILE = Path("/usr/share/sounds/alsa/Front_Center.wav")

# Optional extra command to run on every press, as a list. Examples:
#   ["curl", "-s", "-d", "Dash button pressed", "https://ntfy.sh/YOUR-TOPIC"]
#   ["/home/YOURUSER/dash/my_script.sh"]
EXTRA_COMMAND = None

# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("dash")

BUTTONS = {mac.lower(): name for mac, name in BUTTONS.items()}
last_press = {}

# Set up the LED if gpiozero and a GPIO header are available.
try:
    from gpiozero import LED

    led = LED(LED_PIN)
except Exception as exc:  # not on a Pi, or no GPIO access
    led = None
    log.warning("LED disabled (%s)", exc)


def handle_press(name, mac):
    """Everything that happens when a button is pressed."""
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    log.info("PRESS: %s (%s)", name, mac)

    # 1. Toggle the LED
    if led is not None:
        led.toggle()
        log.info("LED is now %s", "ON" if led.is_lit else "OFF")

    # 2. Log the press to CSV
    new_file = not LOG_FILE.exists()
    with LOG_FILE.open("a", newline="") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["timestamp", "button", "mac"])
        writer.writerow([stamp, name, mac])

    # 3. Play a sound without blocking
    if SOUND_FILE and Path(SOUND_FILE).exists():
        subprocess.Popen(
            ["aplay", "-q", str(SOUND_FILE)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    # 4. Run any extra command
    if EXTRA_COMMAND:
        try:
            subprocess.Popen(EXTRA_COMMAND)
        except OSError as exc:
            log.error("Extra command failed: %s", exc)


def on_packet(pkt):
    if not pkt.haslayer(Ether):
        return
    mac = pkt[Ether].src.lower()
    name = BUTTONS.get(mac)
    if name is None:
        return
    now = time.monotonic()
    if now - last_press.get(mac, float("-inf")) < DEBOUNCE_SECONDS:
        return  # same press, still rejoining the network
    last_press[mac] = now
    try:
        handle_press(name, mac)
    except Exception:
        log.exception("Error while handling press")


def main():
    if not BUTTONS or "aa:bb:cc:dd:ee:ff" in BUTTONS:
        log.warning("Edit BUTTONS at the top of this script with your button's MAC.")
    bpf = " or ".join(f"ether src {mac}" for mac in BUTTONS)
    log.info("Listening for %d button(s)... Ctrl+C to stop.", len(BUTTONS))
    sniff(iface=INTERFACE, filter=bpf, prn=on_packet, store=False)


if __name__ == "__main__":
    main()
