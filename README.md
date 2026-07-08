<img width="1536" height="864" alt="QIQ-WIRE" src="https://github.com/user-attachments/assets/2b32068d-ee4b-4687-b848-46d3b12fb52a" />

# 🛰️ QIQ-WIRE

> **A packet sniffer built from scratch to understand how network protocols actually work.**

QIQ-WIRE is an educational networking project written in Python with the goal of understanding how data moves through a network, one protocol at a time.

Instead of relying on high-level networking libraries, this project manually parses packets using raw sockets, binary unpacking (`struct`), and bitwise operations. The idea is to progressively build a modular networking framework while learning how protocols interact at every layer.

> 🐧 **Currently Linux-only.** Windows support is planned for future releases.

---

# 🎯 Why?

Most packet analyzers hide the interesting part: how packets are actually decoded.

QIQ-WIRE was created to answer questions like:

- 🌐 How does an Ethernet frame become an IPv4 packet?
- 🔌 Where do TCP ports come from?
- 📡 How does DNS translate a domain into an IP address?
- 📦 What information is actually traveling through the network?

Every parser in this project is implemented manually as a learning exercise.

---

# ✨ Current Features

- ✅ Ethernet frame parser
- ✅ IPv4 packet parser
- ✅ TCP segment parser
- ✅ UDP datagram parser
- ✅ DNS packet parser
- ✅ DNS query & response detection
- ✅ DNS domain extraction
- ✅ DNS response IP extraction
- ✅ Live traffic statistics
- ✅ Top DNS domains
- ✅ Top IP addresses
- ✅ Modular parser architecture

---

# 📁 Project Structure

```text
QIQ-WIRE/
│
├── main.py
│
├── parsers/
│   ├── ethernet.py
│   ├── ipv4.py
│   ├── tcp.py
│   ├── udp.py
│   └── dns.py
│
├── constants/
│   └── ports.py
│
├── utils/
│   └── formatters.py
│
└── README.md
```

---

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/<your-user>/QIQ-WIRE.git
cd QIQ-WIRE
```

Run the sniffer:

```bash
sudo python3 main.py
```

Debug mode:

```bash
sudo python3 main.py --debug
```

DNS only:

```bash
sudo python3 main.py --dns
```

TCP only:

```bash
sudo python3 main.py --tcp
```

> ⚠️ Root privileges are required because the project uses raw sockets.
>
> You may have troubles to run it on Windows.

---

# 📚 Supported Protocols

| Protocol | Status |
|----------|:------:|
| Ethernet | ✅ |
| IPv4 | ✅ |
| TCP | ✅ |
| UDP | ✅ |
| DNS | ✅ |
| ICMP | 🚧 |
| HTTP | 🚧 |
| ARP | 📅 |
| IPv6 | 📅 |

---

# 🗺️ Roadmap

## 🚀 Version 1

- [x] Ethernet parser
- [x] IPv4 parser
- [x] TCP parser
- [x] UDP parser
- [x] DNS parser
- [x] DNS statistics
- [x] IP statistics

## ⚙️ Version 2

- [ ] ICMP parser
- [ ] HTTP parser
- [ ] ARP parser
- [ ] Better live dashboard
- [ ] Packet filtering
- [ ] Traffic logging

## 🛡️ Version 3

- [ ] Mini IDS
- [ ] Port scanner
- [ ] Connection tracking
- [ ] Session reconstruction
- [ ] Export to PCAP

## 🌍 Future

- [ ] Windows compatibility
- [ ] IPv6 support
- [ ] Plugin system
- [ ] Web dashboard
- [ ] Performance improvements

---

# 🎓 Learning Goals

This project was built to explore topics such as:

- 🌐 Computer Networks
- 📦 Packet Analysis
- ⚙️ Binary Parsing
- 🔗 Raw Sockets
- 📡 Network Protocols
- 🔐 Cybersecurity Fundamentals
- 🐍 Python Low-Level Networking

---

# 🛠️ Technologies

- 🐍 Python 3
- 🔗 Raw Sockets (`AF_PACKET`)
- 📦 `struct`
- ⚡ Bitwise Operations

---

# ⚠️ Disclaimer

QIQ-WIRE is an educational project.

It was built to learn how networking protocols work internally and should **not** be considered a replacement for professional tools like Wireshark or tcpdump.

---

# 🤝 Contributing

Suggestions, issues and pull requests are always welcome.

Have an idea for a new protocol parser or feature? Feel free to open an issue or submit a PR!

---
