# 📡 Packet Sniffer GUI (GTK + libpcap)

A lightweight packet sniffer with a **graphical user interface** built using **GTK** in C, powered by **libpcap** for real-time packet capture. Displays packet details like source, destination IP, and protocol type.

---

## ✨ Features

- Live packet capture from selected network interface
- GUI built using **GTK 3**
- Detects and lists all available interfaces
- Displays:
  - Source and destination IP addresses
  - Protocol (TCP/UDP/ICMP/Other)
- Start/Stop controls for capture
- Multithreaded: sniffing handled in a separate thread

---

## 🛠️ Requirements

Install the necessary libraries and development packages:

```bash
sudo apt update
sudo apt install libgtk-3-dev libpcap-dev build-essential
```
COMPILATION
```bash
gcc packet_sniffer.c -o packet_sniffer `pkg-config --cflags --libs gtk+-3.0` -lpcap -lpthread

```
RUN
```bash
./packet_sniffer
```
