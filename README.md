# HamraveshTask

Run this task using :

`python test.py -r /path/to/file`

the `time` library is used to measure the time of the program

Some decision :
- I used the `sum` function to count the number of lines since it was easier.
- While trying to find the most malicious ip address I found out that using a nested dictionary is better so I added a "malicious_attemp" field to my dictionary"
- I used a regex for parsing different parts of each line and used an hour group inside the date group to be able to sort the traffic by hour
