# Building a Port Scan Detector: A Hands-On Approach to Network Security

As a Computer Science student with a concentration in cybersecurity, I've always been fascinated by the cat-and-mouse game between attackers and defenders. Recently, I built a Python-based port scan detector from scratch-a tool that mirrors what enterprise intrusion detection systems do at a fundamental level. Here's the story of how I built it and what I learned along the way.

## What is Port Scanning and Why Should You Care?

Before an attacker breaks into your system, they need to find a way in. That's where port scanning comes in.

Think of your computer as a building with 65,535 doors (ports). Each door leads to a different service-port 22 opens to SSH, port 80 to your web server, port 3306 to your MySQL database. An attacker doesn't know which doors are unlocked, so they knock on all of them. That's a port scan.

Tools like `nmap` make this trivially easy:

```bash
nmap -p 1-65535 192.168.1.100
```

This single command probes every possible port on a target machine. For defenders, detecting this reconnaissance activity is critical-it's often the first warning sign that an attack is coming.

## The Challenge

The problem I set out to solve was straightforward: given a list of network connection attempts, identify IP addresses that attempted to connect to more than a specified number of unique destination ports.

Here's what the input data looks like:

```python
connections = [
    ("192.168.1.50", 22),    # IP tried port 22
    ("192.168.1.50", 80),    # same IP tried port 80
    ("192.168.1.50", 443),   # same IP tried port 443
    ("192.168.1.50", 8080),  # same IP tried port 8080
    ("10.0.0.1", 22),        # different IP, only port 22
    ("192.168.1.50", 22),    # duplicate - same IP, same port
]
```

With a threshold of 3, the detector should flag `192.168.1.50` (4 unique ports) but not `10.0.0.1` (only 1 port).

## My Thought Process

Before writing any code, I broke down the problem:

1. **Track unique connections** - I need to ignore duplicates. If an IP hits port 22 five times, that's still just one unique port.

2. **Count per IP** - Each IP address needs its own counter for unique ports accessed.

3. **Threshold comparison** - Only flag IPs that exceed (not just meet) the threshold.

4. **Avoid duplicate alerts** - Once an IP is flagged, don't add it to the results again.

This naturally pointed me toward two data structures: a **set** for tracking unique (IP, port) pairs, and a **dictionary** for counting unique ports per IP.

## The Implementation

Here's the solution I built:

```python
def detect_port_scanners(connections: list[tuple], port_threshold: int) -> list[str]:
    
    unique_connections = set()
    # create set to store unique tuples
    unique_attempts = dict()
    # create a dictionary to count unique connection attempts 
    
    result = []
    
    for c in connections:
        # c -> (ip, port)
        if c not in unique_connections:
            # add to unique connections
            unique_connections.add(c)
            
            if c[0] in unique_attempts:
                unique_attempts[c[0]] += 1
            else:
                unique_attempts[c[0]] = 1
                
            if unique_attempts[c[0]] > port_threshold and c[0] not in result:
                result.append(c[0])

    return result
```

Let me walk through the key decisions:

**Using a Set for Deduplication**

Sets in Python have O(1) lookup time and automatically handle uniqueness. By storing the full `(ip, port)` tuple, I can quickly check if we've seen this exact connection before. This is crucial-without it, an attacker repeatedly hitting the same port would trigger false positives.

**Dictionary for Per-IP Counting**

The dictionary maps each IP to its count of unique ports. When we encounter a new unique connection, we either initialize the counter at 1 or increment it.

**Threshold Check Placement**

I check the threshold immediately after incrementing the counter. This means we flag IPs as soon as they cross the threshold, not after processing all connections. In a real-time system, this would enable faster alerting.

## Testing with Realistic Scenarios

I built three test cases to validate the detector:

**Basic Test** - One clear scanner among normal traffic. Validates the core logic works.

**Edge Cases** - Multiple IPs at or near the threshold, heavy duplicate traffic. This caught a subtle bug in my first implementation where I wasn't properly handling the "greater than" vs "greater than or equal to" distinction.

**Stress Test** - Realistic attack patterns including:
- Common service port scanning (FTP, SSH, HTTP, databases)
- Sequential port scanning (the classic nmap pattern)
- Mixed legitimate and malicious traffic

Here's an example from the stress test:

```python
# Aggressive scanner - common service ports
("185.220.101.50", 21),    # FTP
("185.220.101.50", 22),    # SSH
("185.220.101.50", 23),    # Telnet
("185.220.101.50", 25),    # SMTP
("185.220.101.50", 80),    # HTTP
("185.220.101.50", 443),   # HTTPS
("185.220.101.50", 3389),  # RDP
("185.220.101.50", 3306),  # MySQL
```

This pattern-probing well-known service ports-is exactly what real attackers do during reconnaissance.

## How This Connects to Real-World Security

The logic I implemented here is fundamentally the same as what production intrusion detection systems use. Tools like Snort, Suricata, and Zeek all maintain state about connection patterns and alert when thresholds are crossed.

The main differences in production systems:

| My Implementation | Production IDS |
|-------------------|----------------|
| Reads from a list | Captures packets in real-time |
| Processes after the fact | Analyzes traffic as it flows |
| Simple threshold | Time-windowed thresholds (e.g., 100 ports in 60 seconds) |
| Console output | SIEM integration, automated blocking |

In a production environment, this detector would likely be enhanced with:

- **Time windows** - Only count ports within a sliding time window
- **Whitelisting** - Exclude known vulnerability scanners or internal security tools
- **Rate limiting** - Automatically block IPs that trigger alerts
- **Correlation** - Combine with other indicators like failed logins

## Lessons Learned

Building this tool reinforced several key concepts:

1. **Data structures matter** - Choosing sets and dictionaries made the solution clean and efficient. The wrong choice (like using lists for lookups) would have made it O(n²).

2. **Edge cases are where bugs hide** - The difference between `>` and `>=` is one character but completely changes behavior. Testing with boundary values caught this.

3. **Security is about patterns** - Attackers leave fingerprints. Port scans have distinct patterns (sequential ports, common services) that can be detected algorithmically.

4. **Simple solutions scale** - This same logic, with minor modifications, could process millions of connections. The core algorithm doesn't need to change.

## Eventually..........

I'm planning to extend this project by:

- Adding real-time packet capture using Scapy
- Implementing time-windowed detection
- Building a simple dashboard to visualize scanning activity
- Integrating with firewall rules for automated blocking

Port scanning detection is just the beginning. The same pattern-matching approach applies to detecting brute force attacks, data exfiltration, lateral movement, and countless other threats.

---

*This project is part of my journey into AI safety and security engineering. If you're interested in cybersecurity or building detection tools, feel free to reach out.*
