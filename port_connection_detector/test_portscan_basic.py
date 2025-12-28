from port_scan_detector import detect_port_scanners

connections = [
    ("10.0.0.50", 22),
    ("10.0.0.50", 23),
    ("10.0.0.50", 80),
    ("10.0.0.50", 443),
    ("10.0.0.50", 8080),
    ("172.16.0.5", 22),
    ("172.16.0.5", 22),  # duplicate
    ("172.16.0.5", 80),
    ("192.168.1.1", 443),
]

threshold = 3

# Expected: ["10.0.0.50"]
# 10.0.0.50 hit 5 unique ports
# 172.16.0.5 hit 2 unique ports (duplicate doesn't count)
# 192.168.1.1 hit 1 port

result = detect_port_scanners(connections, threshold)
print(f"Threshold: {threshold}")
print(f"Result: {result}")
print(f"Expected: ['10.0.0.50']")
