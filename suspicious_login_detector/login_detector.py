import re

def find_suspicious_ips(logs: list[str], threshold: int) -> list[str]:

    detector = {}
    passed_threshold = []
    an_ip = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    a_res = r"(failure|success)"
    # create a regex for ips and for result  
    
    for l in logs:
        ip = re.search(an_ip, l)
        res = re.search(a_res, l)
        
        res_value = res.group(0)
        ip_value = ip.group(0)

        print(f"the ip found: {ip.group(0)}, the result found: {res.group(0)}")

        if res_value == "failure":
            if ip_value in detector:
                detector[ip_value] += 1
            else:
                detector[ip_value] = 1
            print(f"ip_value in detector and res_value == 'failure': {detector}")

            if detector[ip_value] > threshold and ip_value not in passed_threshold:
                passed_threshold.append(ip_value)
            
    return passed_threshold
        
    # loop thru logs and set a ip and result var
    
    # if statement if its in the Dictionary alr -> true -> +1
    
def main():
    
    
    FILEPATH = "test_logs_stress.log"
    file_log = []

    try:
        with open(FILEPATH, 'r') as f:    
            for l in f:
                file_log.append(l.strip())
            print(f.read())
            
    except FileNotFoundError:
        print("File not found.")
    print(file_log)

    print(find_suspicious_ips(file_log, threshold=2))
    print('-----------------------RESULT ABOVE THIS LINE:--------------------------')
    
    
if __name__ == "__main__":
    main()


# READ WRITE UP BELOW: 


"""
This function is a script that goes through a log file, converts to a string list, and parses through each line to find suspsious login attempts. 

My thought process for writing it was to use regex as the means for finding the ip address as well as the result(failure or success). 
That way when you find the ip you can add it to a counter - a dictionary (a key, value data structure) to record the occurences of a specific ip address

Note: if you're regex is wrong, this script is useless lol (not totally useless but ineffective)

And feel free to comment out any print statements
# Problem 1: Failed Login Detector (Warm-up)
# Problem
# You're analyzing authentication logs. Each entry has format: "timestamp,ip_address,result"
# where result is either "success" or "failure".
# Write a function that returns all IP addresses with more than threshold failed login attempts.
# Example
# pythonlogs = [
#     "2024-01-15 10:00:00,192.168.1.100,failure",
#     "2024-01-15 10:00:01,192.168.1.100,failure",
#     "2024-01-15 10:00:02,192.168.1.101,success",
#     "2024-01-15 10:00:03,192.168.1.100,failure",
#     "2024-01-15 10:00:04,10.0.0.50,failure",
# ]
# threshold = 2

# # Expected output: ["192.168.1.100"]
# # (192.168.1.100 has 3 failures, 10.0.0.50 only has 1)
# def find_suspicious_ips(logs: list[str], threshold: int) -> list[str]:
#     pass

"""

