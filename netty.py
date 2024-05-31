import tkinter as tk
from scapy.all import sniff
import threading
import os
import sys

class SnifferApp:
    def __init__(self, master, interface):
        self.master = master
        self.interface = interface
        master.title(f"Network Sniffer - {self.interface}")

        self.label = tk.Label(master, text=f"Network Sniffer on {self.interface}")
        self.label.pack()

        self.start_button = tk.Button(master, text="Start", command=self.start_sniffing)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Stop", command=self.stop_sniffing)
        self.stop_button.pack()

        self.log = tk.Text(master)
        self.log.pack()

        self.sniffing = False

    def packet_callback(self, packet):
        try:
            protocol = packet.proto
            src_ip = packet[1].src
            dst_ip = packet[1].dst
            log_entry = f"Protocol: {protocol}, Source IP: {src_ip}, Destination IP: {dst_ip}\n"
            print(log_entry)  # Print to console for debugging
            self.log.insert(tk.END, log_entry)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_sniffing(self):
        self.sniffing = True
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def sniff_packets(self):
        print(f"Starting sniffing on {self.interface}")  # Debugging statement
        sniff(iface=self.interface, prn=self.packet_callback, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False
        self.sniff_thread.join()
        print("Stopped sniffing")  # Debugging statement

def main():
    # Check for root permissions
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run it with sudo.")
        sys.exit(1)

    # Check for command-line arguments
    if len(sys.argv) != 2:
        print("Usage: sudo python netty.py <interface> :>")
        sys.exit(1)

    interface = sys.argv[1]

    root = tk.Tk()
    app = SnifferApp(root, interface)
    root.mainloop()

if __name__ == "__main__":
    main()
