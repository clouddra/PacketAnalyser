Name: Chong Yun Long
Matriculation : A0072292H

Part 1

Compilation
-----------
javac PacketCount.java

Execution
---------
java PacketCount

When running the program. There will be 1 graphical prompts for selection of the hex dump file.

Development and Testing
-----------------------
Developed on NetBeans IDE 7.2, Java: 1.7.0 on Windows Platform

Sample output
-----------------------
total number of Ethernet (IP + ARP) packets = 4021
total number of IP packets 4011
total number of ARP packets 10
total number of ICMP packets 1098
total number of TCP packets 1645
total number of UDP packets 1262
total number of Ping packets 1097
total number of DHCP packets 14
total number of DNS packets 1171


Part 2
This program processes 'A' Queries (type 1) as well as 'PTR' Queries (type 12)


Compilation
-----------
javac DNSAnalyser.java

Execution
---------
java DNSAnalyser

When running the program. There will be 1 graphical prompts for selection of the hex dump file.

Development and Testing
-----------------------
Developed on NetBeans IDE 7.2, Java: 1.7.0 on Windows Platform

Sample output
-----------------------

----------------------
DNS Transaction
----------------------
transaction_id = ddbe
Questions = 1
Answers RR = 1
Authority RRs = 4
Additonal RRs = 4
Queries:
	Name = 104.61.239.216.in-addr.arpa.
	Type = 12
	Class = 1
Answers:
	Name = 104.61.239.216.in-addr.arpa.
	Type =  12
	Class = 1
	Time to live = 86180
	Data length = 28
	Domain Name = sin01s01-in-f104.1e100.net.

----------------------
DNS Transaction
----------------------
transaction_id = a99b
Questions = 1
Answers RR = 2
Authority RRs = 4
Additonal RRs = 4
Queries:
	Name = safebrowsing-cache.google.com.
	Type = 1
	Class = 1
Answers:
	Name = safebrowsing-cache.google.com.
	Type =  5
	Class = 1
	Time to live = 106251
	Data length = 23
	CNAME = safebrowsing.cache.l.google.com.

	Name = safebrowsing.cache.l.google.com.
	Type =  1
	Class = 1
	Time to live = 57
	Data length = 4
	Addr = 74.125.162.91


total number of DNS packets = 1171
total number of DNS transactions 584