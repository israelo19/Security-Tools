# How to Use This Document

# Read the problem carefully - understand inputs, outputs, constraints
# Think before coding - spend 2-3 minutes planning your approach
# Write pseudocode first - outline your solution in plain English
# Code the solution - implement step by step
# Test with examples - trace through with the provided test cases
# Compare to solution - only after attempting!

# # Problem 2: Port Scan Detector
# Difficulty: Medium | Time: 25 minutes | Topics: Sets, Dictionaries, Grouping
# Problem
# You're building an intrusion detection feature. A port scan is when a single IP probes
# many different ports in a short time.
# Given a list of network connection attempts, identify IPs that attempted to connect to
# more than port_threshold unique destination ports.
# Example
# pythonconnections = [
#     ("192.168.1.50", 22),    # IP tried port 22
#     ("192.168.1.50", 80),    # same IP tried port 80
#     ("192.168.1.50", 443),   # same IP tried port 443
#     ("192.168.1.50", 8080),  # same IP tried port 8080
#     ("10.0.0.1", 22),        # different IP, only port 22
#     ("192.168.1.50", 22),    # duplicate - same IP, same port
# ]
# port_threshold = 3

# # Expected output: ["192.168.1.50"]
# # (192.168.1.50 tried 4 unique ports: 22, 80, 443, 8080)
# # (10.0.0.1 only tried 1 unique port)
# Your Solution Space
# pythondef detect_port_scanners(connections: list[tuple], port_threshold: int) -> list[str]:
#     # YOUR CODE HERE
#     pass

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
        else:
            pass

    return result

    # iterate through the connections & ip, and count
    
    # if statement gt threshold then add to results list


def main():
    pythonconnections = [
    ("192.168.1.50", 22),    # IP tried port 22
    ("192.168.1.50", 80),    # same IP tried port 80
    ("192.168.1.50", 443),   # same IP tried port 443
    ("192.168.1.50", 8080),  # same IP tried port 8080
    ("10.0.0.1", 22),        # different IP, only port 22
    ("192.168.1.50", 22),    # duplicate - same IP, same port
    ]
    thresh = 3

    print(detect_port_scanners(connections=pythonconnections, port_threshold=thresh))
    
    
if __name__ == "__main__":
    main()
    

