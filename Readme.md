Provided a vdom and a list of ips and urls, generate the necessary output to paste into a fortigate.

The input file can be either a .txt or .csv.

.txt files should contain only your entries, each on its own line, and no extra characters.
A valid .txt entry is either an IP/CIDR (ex. 192.168.1.0/24), an IP/Netmask (ex. 192.168.1.0/255.255.255.0), or a URL (ex. www.purple.com).

.csv files should contain 4 fields:
1. IP, IP/CIDR, IP/Netmask or URL
2. Netmask (needed if you do not provide a CIDR in the previous field)
3. Custom Name for the object
4. Interface to attach object to

.csv\'s should be formatted similarly to an Excel .csv

Requires Python 3