# Building a Failed Login Detector: Catching Brute Force Attacks with Python and Regex

Brute force attacks are one of the oldest tricks in the book-and they still work. Attackers hammer login pages with thousands of password guesses, hoping to stumble onto valid credentials. The good news? These attacks leave obvious fingerprints in your logs. I built a Python tool to find them.

## The Problem: Needle in a Haystack

Authentication logs are noisy. Every login attempt-successful or not-gets recorded. A typical server might log thousands of entries per day. Buried in that noise could be an attacker systematically guessing passwords for a single account.

Here's what raw authentication logs look like:

```
2024-01-15 10:00:00,192.168.1.100,failure
2024-01-15 10:00:01,192.168.1.100,failure
2024-01-15 10:00:02,192.168.1.101,success
2024-01-15 10:00:03,192.168.1.100,failure
2024-01-15 10:00:04,10.0.0.50,failure
```

See the pattern? `192.168.1.100` failed three times in a row. That's suspicious. `10.0.0.50` only failed once-probably just a typo. My goal was to build a detector that automatically flags IPs with too many failed attempts.

## My Thought Process

Before writing code, I mapped out what needed to happen:

1. **Parse each log line** - Extract the IP address and the result (success/failure)
2. **Track failures per IP** - Use a dictionary to count failed attempts
3. **Ignore successes** - We only care about failures
4. **Flag IPs above threshold** - Return any IP that exceeds our limit

The parsing step is where regex comes in. Each log line has a predictable structure, but I didn't want to rely on splitting by commas (what if the format changes slightly?). Regex gives me flexibility to find patterns anywhere in the line.

## The Implementation

Here's the core function:

```python
import re

def find_suspicious_ips(logs: list[str], threshold: int) -> list[str]:

    detector = {}
    passed_threshold = []
    an_ip = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    a_res = r"(failure|success)"
    
    for l in logs:
        ip = re.search(an_ip, l)
        res = re.search(a_res, l)
        res_value = res.group(0)
        ip_value = ip.group(0)

        if res_value == "failure":
            if ip_value in detector:
                detector[ip_value] += 1
            else:
                detector[ip_value] = 1

            if detector[ip_value] > threshold and ip_value not in passed_threshold:
                passed_threshold.append(ip_value)
            
    return passed_threshold
```

Let me break down the key decisions:

**Regex for IP Addresses**

```python
an_ip = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
```

This pattern matches the standard IPv4 format: four groups of 1-3 digits separated by dots. It's simple and effective. Note: if your regex is wrong, this script is useless-or at least ineffective. I learned this the hard way during testing.

**Regex for Results**

```python
a_res = r"(failure|success)"
```

This captures either "failure" or "success" from anywhere in the log line. The parentheses create a capture group so I can extract the matched value.

**Only Counting Failures**

An earlier version of my code had a bug-I was resetting the counter whenever a success appeared. The fix was simple: wrap all the counting logic inside `if res_value == "failure"`. Successes are now completely ignored, which is exactly what we want.

**Dictionary for Counting**

```python
detector = {}
```

The dictionary maps each IP to its failure count. When we see a new IP fail, we initialize it at 1. Subsequent failures increment the count. This gives us O(1) lookups and updates.

## Reading from Log Files

The detector function works on a list of strings, but real logs live in files. Here's how I load them:

```python
def main():
    FILEPATH = "login_logs.log"
    file_log = []

    try:
        with open(FILEPATH, 'r') as f:    
            for l in f:
                file_log.append(l.strip())
    except FileNotFoundError:
        print("File not found.")

    print(find_suspicious_ips(file_log, threshold=2))
```

The `with open()` context manager handles file closing automatically-no need for manual `f.close()` calls. Each line gets stripped of whitespace and added to the list.

## Testing with Realistic Scenarios

I built three test files to validate the detector:

**Basic Test** - One IP with 5 failures, others with minimal activity
```
2024-01-15 08:01:12,10.0.0.25,failure
2024-01-15 08:01:45,10.0.0.25,failure
2024-01-15 08:02:03,10.0.0.25,failure
...
```
Expected result with threshold=2: `["10.0.0.25"]`

**Edge Cases** - Multiple suspicious IPs, successes mixed in
```
2024-02-20 12:00:00,203.0.113.5,failure
2024-02-20 12:00:15,203.0.113.5,failure
2024-02-20 12:03:00,203.0.113.5,success   # doesn't reset count!
2024-02-20 12:03:30,203.0.113.5,failure
```
This test validates that successful logins don't affect the failure count.

**Stress Test** - 26 log entries with multiple attackers and legitimate traffic
```
2024-03-10 00:01:00,45.33.32.156,failure
2024-03-10 00:02:00,45.33.32.156,failure
2024-03-10 00:04:00,45.33.32.156,failure
2024-03-10 00:09:00,45.33.32.156,failure
2024-03-10 00:14:00,45.33.32.156,failure
2024-03-10 00:19:00,45.33.32.156,failure
```
This IP has 6 failures spread across the log-a persistent attacker.

## Real-World Security Applications

What I built is a simplified version of what production security tools do every day. Here's how it connects to the real world:

**Brute Force Detection**

Failed login detectors are the first line of defense against credential stuffing and password spraying attacks. When an attacker tries thousands of passwords against a single account, or tries one common password against thousands of accounts, the failure patterns are detectable.

**SIEM Integration**

In enterprise environments, tools like Splunk, Elastic SIEM, or Microsoft Sentinel ingest authentication logs and run similar detection logic. They correlate failed logins with other indicators-geographic anomalies, impossible travel, known bad IPs-to build a complete picture.

**Automated Response**

Production systems don't just detect-they respond. Common actions include:
- Temporary IP blocking after N failures
- Account lockout after N failures per user
- CAPTCHA challenges for suspicious sessions
- Alerting the security team for investigation

**The Log Format Matters**

My tool assumes a specific log format: `timestamp,ip_address,result`. Real systems have to handle dozens of different formats-Windows Event Logs, Linux auth.log, application-specific formats. That's why regex flexibility is valuable.

## Lessons Learned

**Regex is powerful but fragile** - A single wrong character in your pattern means nothing matches. Test your regex separately before integrating it.

**Successes shouldn't reset failures** - This was a real bug I had to fix. In security, failed attempts accumulate over time. A successful login between failures doesn't make the failures disappear.

**Data structures simplify everything** - Using a dictionary for counting made the code clean and efficient. Trying to do this with nested loops would have been painful.

**Test at the boundaries** - Edge cases (exactly at threshold, lots of duplicates, mixed success/failure) revealed bugs that normal testing missed.

## What's Next

This detector could be extended with:

- **Time windows** - Only count failures within the last hour
- **User-based detection** - Track failures per username, not just IP
- **Velocity detection** - Flag IPs that fail too fast (10 attempts in 1 second)
- **Geo-correlation** - Flag failures from unusual locations
- **Real-time processing** - Monitor logs as they're written

Brute force detection is foundational, but it's just the beginning. The same pattern-matching approach applies across security-detecting port scans, data exfiltration, lateral movement, and more.

---

*This project is part of my journey into security engineering and AI safety. The code is available for anyone learning log analysis and detection engineering.*
