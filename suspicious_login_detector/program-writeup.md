This function is a script that goes through a log file, converts to a string list, and parses through each line to find suspsious login attempts. 

My thought process for writing it was to use regex as the means for finding the ip address as well as the result(failure or success). 
That way when you find the ip you can add it to a counter - a dictionary (a key, value data structure) to record the occurences of a specific ip address

Note: if you're regex is wrong, this script is useless lol (not totally useless but ineffective)

And feel free to comment out any print statements  
Problem 1: Failed Login Detector (Warm-up)  
Problem
You're analyzing authentication logs. Each entry has format: "timestamp,ip_address,result" where result is either "success" or "failure". Write a function that returns all IP addresses with more than threshold failed login attempts.  
Example  

` pythonlogs = [  "2024-01-15 10:00:00,192.168.1.100,failure", "2024-01-15 10:00:01,192.168.1.100,failure",  "2024-01-15 10:00:02,192.168.1.101,success",  "2024-01-15 10:00:03,192.168.1.100,failure",  "2024-01-15 10:00:04,10.0.0.50,failure",]
 threshold = 2`

  Expected output: ["192.168.1.100"]  
  
  (192.168.1.100 has 3 failures, 10.0.0.50 only has 1)

