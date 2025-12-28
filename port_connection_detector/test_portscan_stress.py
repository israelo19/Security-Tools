from port_scan_detector import detect_port_scanners

connections = [
    # Aggressive scanner - common service ports
    ("185.220.101.50", 21),    # FTP
    ("185.220.101.50", 22),    # SSH
    ("185.220.101.50", 23),    # Telnet
    ("185.220.101.50", 25),    # SMTP
    ("185.220.101.50", 80),    # HTTP
    ("185.220.101.50", 443),   # HTTPS
    ("185.220.101.50", 3389),  # RDP
    ("185.220.101.50", 3306),  # MySQL
    ("185.220.101.50", 5432),  # PostgreSQL
    ("185.220.101.50", 6379),  # Redis
    
    # Normal web traffic
    ("10.10.10.5", 443),
    ("10.10.10.5", 443),
    ("10.10.10.5", 80),
    
    # Another scanner - sequential ports (classic nmap pattern)
    ("91.240.118.200", 1),
    ("91.240.118.200", 2),
    ("91.240.118.200", 3),
    ("91.240.118.200", 4),
    ("91.240.118.200", 5),
    ("91.240.118.200", 6),
    
    # Legitimate server talking to multiple services
    ("192.168.50.10", 53),     # DNS
    ("192.168.50.10", 443),    # HTTPS
    
    # Borderline suspicious
    ("172.217.14.99", 80),
    ("172.217.14.99", 443),
    ("172.217.14.99", 8080),
    ("172.217.14.99", 8443),
    ("172.217.14.99", 9000),   # 5 ports total
    
    # More duplicates from the aggressive scanner
    ("185.220.101.50", 22),
    ("185.220.101.50", 80),
    
    # Single connection
    ("8.8.8.8", 53),
]

threshold = 4

# Expected: ["185.220.101.50", "91.240.118.200", "172.217.14.99"]
# 185.220.101.50 hit 10 unique ports (aggressive scanner)
# 91.240.118.200 hit 6 unique ports (sequential scan)
# 172.217.14.99 hit 5 unique ports (borderline)
# 10.10.10.5 hit 2 unique ports
# 192.168.50.10 hit 2 unique ports
# 8.8.8.8 hit 1 port

result = detect_port_scanners(connections, threshold)
print(f"Threshold: {threshold}")
print(f"Result: {result}")
print(f"Expected: ['185.220.101.50', '91.240.118.200', '172.217.14.99']")
print(f"\nBreakdown:")
print(f"  185.220.101.50 - 10 unique ports (common services scan)")
print(f"  91.240.118.200 - 6 unique ports (sequential scan)")
print(f"  172.217.14.99  - 5 unique ports")
