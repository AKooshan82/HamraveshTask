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
with open(file_path, "r") as file:
    for line in file:
        input()
        match = re.search(pattern,line)
        if match is not None:
            print(match.group("ip_address"))
