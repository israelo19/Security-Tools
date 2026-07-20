# Security-Tools

A collection of security detection tools built from scratch to understand how real-world intrusion detection systems work under the hood.

## Why This Exists

As a Computer Science student with a cybersecurity concentration, I wanted to go beyond theory. These tools are my hands-on exploration of detection engineering—the art of finding attackers by analyzing patterns in logs and network traffic.

Each tool in this repo solves a real security problem that enterprises face daily. By building them myself, I'm learning:
- How attackers leave fingerprints in system logs
- Pattern recognition techniques used by SIEM platforms
- The data structures and algorithms behind security tooling
- Python scripting for log analysis and automation

## Current Tools

| Tool | Description | Key Concepts |
|------|-------------|--------------|
| [suspicious_login_detector](./suspicious_login_detector) | Identifies IPs with excessive failed login attempts (brute force detection) | Regex parsing, dictionaries, threshold alerting |
| [port_connection_detector](./port_connection_detector) | Flags IPs scanning multiple ports (port scan detection) | Sets, deduplication, network reconnaissance |

## Running the Tools

Each tool can be run standalone:

```bash
# Failed login detector
cd suspicious_login_detector
python3 login_detector.py

# Port scan detector
cd port_connection_detector
python3 port_scan_detector.py
```

## About Me

I'm a Senior at the University of Maryland studying Computer Science with a concentration in cybersecurity. My background includes network security work at Cisco, and I'm currently exploring the intersection of AI safety and security engineering.

---
*This project is part of my journey into security engineering and AI safety.*  

*Built for learning. Inspired by real-world security challenges.*
