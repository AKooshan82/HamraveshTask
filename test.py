import argparse
import os
import re


parser = argparse.ArgumentParser(prog='LogChecker',description='Hamravesh Task',add_help=False)
parser.add_argument('-r','--route',type=str,help='File directory')


args = parser.parse_args()

file_path = args.route

if os.path.isfile(file_path) & (file_path.endswith(".log") or file_path.endswith(".txt")):
    print("This is a valid file path")
else:
    print("This isn't a valid file path")
    exit()

num_lines = sum(1 for _ in open(file_path))
print(num_lines)

pattern = r"(?P<ip_address>\d{1,3}.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\D{1,5})(?P<date>\[\d{2}\/\D{3}\/\d{4}\:\d{2}\:\d{2}\:\d{2} \+0000\])\D(?P<message>\"\w+[^\"]+\")\D(?P<error_code>\d{1,3})\D(?P<bite_size>\d{1,10})\D{5}(?P<user_agent>\"[^\"]+\")"

unique_ips = set()
errors= 0

corrupt_lines = 0
with open(file_path, "r") as file:
    for line in file:
        match = re.search(pattern,line)
        if match is not None:
            unique_ips.add(match.group("ip_address"))
            if bool(re.search("^[4-5]",match.group("error_code"))) :
                errors+=1
        else:
            corrupt_lines+=1

true_error_rate = (errors/ (num_lines - corrupt_lines ) )*100
print(f"Number of Corrupted Lines : {corrupt_lines}")
print(f"Number of Lines(Requests) :{num_lines}")
print(f"Number of Unique Ip addresses:{len(unique_ips)}")
print("Error rate is (number of 5xx and 4xx requests):%.2f"%true_error_rate)

