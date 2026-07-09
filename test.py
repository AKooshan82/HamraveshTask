import argparse
import os
import re
import time

start_time = time.perf_counter()

parser = argparse.ArgumentParser(prog='LogChecker',description='Hamravesh Task',add_help=False)
parser.add_argument('-r','--route',type=str,help='File directory')
parser.add_argument('--top_n',default=0,type=int,help="just check the top requestions")


args = parser.parse_args()

file_path = args.route
top_lines = args.top_n

if os.path.isfile(file_path) & (file_path.endswith(".log") or file_path.endswith(".txt")):
    print("This is a valid file path")
else:
    print("This isn't a valid file path")
    exit()

num_lines = sum(1 for _ in open(file_path))
print(num_lines)

pattern = r"(?P<ip_address>\d{1,3}.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\D{1,5})(?P<date>\[\d{2}\/\D{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2} \+0000\])\D(?P<message>\"\w+[^\"]+\")\D(?P<error_code>\d{1,3})\D(?P<byte_size>\d{1,10})\D{5}(?P<user_agent>\"[^\"]+\")"

unique_ips = set()
traffic = {}
errors= 0
lines=0
corrupt_lines = 0
with open(file_path, "r") as file:
    for line in file:
        match = re.search(pattern,line)
        if match is not None:
            #unique ips
            unique_ips.add(match.group("ip_address"))
            #ips_with most traffic
            bytes_sent = int(match.group("byte_size"))
            if match.group("ip_address") not in traffic:
                traffic[match.group("ip_address")] = {
                    "bytes" : 0,
                    "malicious_attemp" : 0
                }
            traffic[match.group("ip_address")]["bytes"]+=bytes_sent
            #error rate
            if bool(re.search("^5",match.group("error_code"))) :
                errors+=1
            if bool(re.search("^4",match.group("error_code"))) :
                errors+=1
                traffic[match.group("ip_address")]["malicious_attemp"]+=1
        #corrupt lines
        else:
            corrupt_lines+=1


top_10 = sorted(traffic.items(), key=lambda item: item[1]["bytes"], reverse=True)[:10]
top_10_malicious = sorted(traffic.items(), key=lambda item: item[1]["malicious_attemp"], reverse=True)[:10]
true_error_rate = (errors/ (num_lines - corrupt_lines ) )*100
print(f"Number of Corrupted Lines : {corrupt_lines}")
print(f"Number of Lines(Requests) :{num_lines}")
print(f"Number of Unique Ip addresses:{len(unique_ips)}")
print("Error rate is (number of 5xx and 4xx requests):%.2f %%"%true_error_rate)
print("==================================")
print("Top 10 IPs by traffic:")
for ip, info in top_10:
    print(ip, info["bytes"])
print("==================================")
print("Top 10 Ips with the most 4xx errors :")
for ip, info in top_10_malicious:
    print(ip, info["malicious_attemp"])

end_time = time.perf_counter()
execution_time = end_time - start_time
print("==================================")

print("Program took %.2f seconds" %execution_time)

