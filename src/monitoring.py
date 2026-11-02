
import argparse
import time
from collections import deque

from scapy.all import sniff, IP, ICMP

from config_loader import load_config
from quarantine import connect, quarantine

CONFIG = load_config()["quarantine"]["detection"]

THRESHOLD = CONFIG["threshold"]
WINDOW = CONFIG["window_seconds"]

VM_IP = "10.0.0.8"
INTERFACE = "tap25f97fea-45"

timestamps = deque()
alert_triggered = False
APPLY_QUARANTINE = False

def process_packet(packet):
    global alert_triggered

    if IP not in packet or ICMP not in packet:
        return

    if packet[IP].src != VM_IP:
        return

    # ICMP type 8 = Echo Request (ping)
    if packet[ICMP].type != 8:
        return

    now = time.monotonic()
    timestamps.append(now)

    # Rimuove i pacchetti fuori dalla finestra
    while timestamps and now - timestamps[0] > WINDOW:
        timestamps.popleft()

    count = len(timestamps)

    print(f"[ICMP] {VM_IP}: {count} richieste negli ultimi {WINDOW}s")


    if count > THRESHOLD and not alert_triggered:
        alert_triggered = True
        print(f"[ALERT] Soglia superata: {count} > {THRESHOLD}")

        try:
            conn = connect()
            quarantine(conn, dry_run=not APPLY_QUARANTINE)

            if APPLY_QUARANTINE:
                print("[QUARANTENA] Richiesta di isolamento completata")
            else:
                print("[SIMULAZIONE] Richiesta di quarantena completata")

        except Exception as error:
            print(f"[ERRORE] Quarantena simulata non riuscita: {error}")

def main():
    parser = argparse.ArgumentParser(
        description="VM Quarantine - ICMP Traffic Monitor"
    )
    parser.add_argument(
        "--interface",
        default=INTERFACE,
        help="Interfaccia di rete da monitorare"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Applica realmente la quarantena al superamento della soglia"
    )
    args = parser.parse_args()
    global APPLY_QUARANTINE
    APPLY_QUARANTINE = args.apply

    print(f"Monitoraggio ICMP su {args.interface}")
    print(f"VM monitorata: {VM_IP}")
    print(f"Soglia: oltre {THRESHOLD} richieste in {WINDOW} secondi")

    sniff(
        iface=args.interface,
        filter=f"icmp and src host {VM_IP} and icmp[0] = 8",
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    main()
