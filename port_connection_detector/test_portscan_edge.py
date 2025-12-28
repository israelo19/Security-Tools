from port_scan_detector import detect_port_scanners

connections = [
    ("203.0.113.10", 21),
    ("203.0.113.10", 22),
    ("203.0.113.10", 23),    # exactly 3 ports
    ("198.51.100.5", 80),
    ("198.51.100.5", 443),
    ("198.51.100.5", 8080),
    ("198.51.100.5", 8443),  # 4 unique ports
    ("192.0.2.99", 22),
    ("192.0.2.99", 22),      # duplicate
    ("192.0.2.99", 22),      # duplicate again
    ("192.0.2.99", 80),      # only 2 unique
    ("45.33.32.10", 1),
    ("45.33.32.10", 2),
    ("45.33.32.10", 3),
    ("45.33.32.10", 4),
    ("45.33.32.10", 5),      # 5 unique ports - clear scanner
]

threshold = 3

# Expected: ["198.51.100.5", "45.33.32.10"]
# 203.0.113.10 hit exactly 3 (not GREATER than threshold)
# 198.51.100.5 hit 4 unique ports
# 192.0.2.99 hit only 2 unique (duplicates don't count)
# 45.33.32.10 hit 5 unique ports

result = detect_port_scanners(connections, threshold)
print(f"Threshold: {threshold}")
print(f"Result: {result}")
print(f"Expected: ['198.51.100.5', '45.33.32.10']")
