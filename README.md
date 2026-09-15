# Building an IDS using Python

### Tools and Libraries Used
- `Python`: for building the logic and handling the CLI.
- `Scapy`: to capture and parse newwork packets.
- `argparse`: to allow command-line arguments for interface selection and filtering. 

### Project Tree
```
.
├── docs
│   └── Bai-tap-01_Packet_Capture_Parser_IDS.pdf
├── __pycache__
│   └── main.cpython-311.pyc
├── README.md
├── src
│   ├── main.py
│   ├── parse_application.py
│   ├── parse_network.py
│   ├── parse_transport.py
│   └── __pycache__
│       ├── main.cpython-311.pyc
│       ├── parse_application.cpython-311.pyc
│       ├── parse_network.cpython-311.pyc
│       └── parse_transport.cpython-311.pyc
├── TEST
│   └── BaiTap1
│       └── 2.YeuCauChucNang
│           ├── LiveCapture
│           │   └── image.png
│           └── PCAP_Import
│               └── image.png
└── ultimate_wireshark_protocols_pcap_220213.pcap
```

### Use AI
- Model: `Big Pickle (OpenCode)'
- AI helps in `src/parse_application.py` 

### References
[1] https://medium.com/@mujtabaeisa9/building-a-packet-sniffer-in-python-as-a-cybersecurity-student-c24c8a2572d1