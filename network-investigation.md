# Scenario
The victim is Falsimentis, a small (fictitious) corporation based in Los Angeles, California, that produces artificial intelligence hardware and software. On Thursday the CEO decided to take the employees out to lunch. The CEO recalls locking their screen and leaving for lunch around 11:50 AM. Returning from lunch around 1:05 PM, the CEO noticed their computer had rebooted.The message is a ransom note from a group of threat actors calling themselves the Midnite Meerkats. The note states that the Midnite Meerkats have control of the victim's systems, and unless the victim pays the ransom within 24 hours, the victim's files will be deleted. The URL that contains the ransom note is https://midnitemeerkats.com/note/.

The CEO contacted the system administrator, who collected various pieces of evidence. The system administrator was able to collect a packet capture of the internal network traffic that Falsimentis was recording for an upcoming audit by one of their large customers. The system administrator was also able to collect logs from a Squid proxy.

## Timelines

   * The CEO locked their workstation and left for lunch at around 11:50 AM.
   * The CEO returned from lunch and logged on to their workstation at around 1:05 PM.
   * The ransom note popped up after the CEO logged on.
   * The ransom note is hosted at https://midnitemeerkats.com/note/
   * The note states the victim has 24 hours to pay, or their files will be deleted.
   * Compromised systems
       * 172.16.42.107 (FM-CEO)
         
# Getting started
```
$ cd ~/labs/falsimentis/ $ ls -l access.log -rw-r--r-- 1 sec504 sec504 25915052 Aug 12 2021 access.log

$ wc -l access.log 177456 access.log

$ head access.log 1584606106.376 71 172.16.42.108 TAG_NONE/200 0 CONNECT 151.101.197.209:443 - ORIGINAL_DST/151.101.197.209 - 1584606106.453 69 172.16.42.108 TCP_MISS/200 216782 GET https://secure.img1-fg.wfcdn.com/im/33758501/resize-h630-w1200%5Ecompr-r85/3949/39499404/.jpg - ORIGINAL_DST/151.101.197.209 image/webb
```
### Using the grep command, we will search through the access.log file for midnitemeerkats
```
$ grep midnitemeerkats access.log 1584648356.572 175 172.16.42.107 TCP_MISS/301 671 GET http://www.midnitemeerkats.com/note - ORIGINAL_DST/69.163.156.144 text/html 1584648359.613 2018 172.16.42.107 TCP_MISS/301 461 GET https://www.midnitemeerkats.com/note - ORIGINAL_DST/69.163.156.144 text/html 1584648360.761 569 172.16.42.107 TCP_MISS/200 4404 GET https://midnitemeerkats.com/note/ - ORIGINAL_DST/69.163.156.144 text/html 1584648360.983 51 172.16.42.107 TCP_MISS/200 1873 GET https://midnitemeerkats.com/wp-content/plugins/memberpress/css/ui/theme.css? - ORIGINAL_DST/69.163.156.144 text/css
```
The Squid log output features multiple fields separated by spaces. We're interested in three key fields: request time (first), requesting client (third), and requested URL (seventh). To extract these, use the provided awk command.
```
$ awk '/midnitemeerkats/ {print $1, $3, $7}' access.log 1584648356.572 172.16.42.107 http://www.midnitemeerkats.com/note 1584648359.613 172.16.42.107 https://www.midnitemeerkats.com/note 1584648360.761 172.16.42.107 https://midnitemeerkats.com/note/ 1584648360.983 172.16.42.107 https://midnitemeerkats.com/wp-content/plugins/memberpress/css/ui/theme.css?
```
The trimmed output is clearer than the original log, yet the timestamp is in POSIX time format, counting seconds since January 1st, 1970, 00:00:00 UTC. Squid logs append millisecond resolution to the timestamp. To present POSIX time in a human-readable format, employ the awk strftime function as illustrated here:
$ sec504@slingshot:/labs/falsimentis$ TZ=America/Los_Angeles awk '/midnitemeerkats/ {print strftime("%T", $1), $3, $7}' access.log
13:05:56 172.16.42.107 http://www.midnitemeerkats.com/note
13:05:59 172.16.42.107 https://www.midnitemeerkats.com/note
13:06:00 172.16.42.107 https://midnitemeerkats.com/note/
13:06:00 172.16.42.107 https://midnitemeerkats.com/wp-content/plugins/memberpress/css/ui/theme.css?  

## Looking for Beacons in access.log
Check for network beacons by identifying numerous requests to the same URL at consistent time intervals. Instead of awk, utilize findbeacons.py, a tool specifically designed for locating beacons. Specify the time interval with the -i argument and set a minimum number of beacon requests using the -c argument. findbeacons.py output reveals http://www1-google-analytics.com/collect with thousands of 5-second interval packets. The URL is suspicious due to the high volume of evenly spaced requests and its similarity to the legitimate www.google-analytics.com.
```
$ sec504@slingshot:~/labs/falsimentis$ ./findbeacons.py  -i 5 -c 10 172.16.42.107 access.log
Sites that had at least 10 5-second intervals
  193 - https://push.services.mozilla.com/
   11 - 172.217.11.162:443
   43 - https://px.moatads.com/pixel.gif?
   12 - 216.58.217.194:443
   20 - 172.217.5.194:443
   11 - https://t.wayfair.com/b.php?
   11 - https://att-app.quantummetric.com/?
   10 - https://a.espncdn.com/combiner/i?
 3268 - http://www1-google-analytics.com/collect
   28 - https://start.specless.tech/report/1
   11 - https://apx.moatads.com/pixel.gif?
sec504@slingshot:~/labs/falsimentis$ 
```
## Finding more compromised hosts
To find additional hosts in the network that are compromised, pivot on the domain www1-google-analytics.com by searching for it in the access.log file as shown.
```
$ sec504@slingshot:~/labs/falsimentis$ awk '/www1-google-analytics.com/ {print $3}' access.log | sort -u
172.16.42.103
172.16.42.105
172.16.42.107
172.16.42.109
sec504@slingshot:~/labs/falsimentis$ 
```
## Finding even more compromised hosts
Now, we shift focus from the access.log file, which only captures HTTP and HTTPS traffic through the proxy, potentially missing non-standard port activity. Let's pivot by examining the packet capture file. To proceed, extract the IP address of www1-google-analytics.com from the access.log file, as demonstrated here:
```
$ sec504@slingshot:~/labs/falsimentis$ grep www1-google-analytics.com access.log | head -n 1
1584638136.869    179 172.16.42.107 TCP_MISS/200 62808 POST http://www1-google-analytics.com/collect - ORIGINAL_DST/167.172.201.123 text/html
sec504@slingshot:~/labs/falsimentis$ 
```
capinfos from Wireshark provides statistics on a pcap file, including capture time, packet count, and file size. Running this command allows you to examine the characteristics of the "falsimentis.pcap" file's network traffic.
```
$ sec504@slingshot:~/labs/falsimentis$ capinfos falsimentis.pcap
File name:           falsimentis.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 262144 bytes
Number of packets:   5,431 k
File size:           3,841 MB
Data size:           3,754 MB
Capture duration:    43474.341653 seconds
First packet time:   2020-03-19 08:14:39.748124
Last packet time:    2020-03-19 20:19:14.089777
Data byte rate:      86 kBps
Data bit rate:       690 kbps
Average packet size: 691.30 bytes
Average packet rate: 124 packets/s
SHA256:              d2da069223e7648570a056b2c579cdd7c3288052d41b4428f7d505c9b8ff4b8e
RIPEMD160:           f249abe5a5a81fd04fecdac2eb4547de8a5fed34
SHA1:                b6d14ec09dab4f228994b0ed8e3ff21e743bfaba
Strict time order:   False
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 5431607
sec504@slingshot:~/labs/falsimentis$ 
```
We do not want to open this packet capture on Wireshark, as once Wireshark exceeds 250,000 to 500,000 it gets very sluggish and it is ver hard to get any answers from that utility. Instead, we are going to use TCPDump to collect information, parsing the output file with Unix command line tools here on my linux system.
Here we can see the IP address of www1-google-analytics.com is 167.172.201.123. Now we can search through the packet capture file falismentis.pcap for traffic destined to this IP as shown here
```
$ sec504@slingshot:~/labs/falsimentis$ tcpdump -nr falsimentis.pcap dst host 167.172.201.123 | cut -d ' ' -f 3 | cut -d '.' -f 1-4 | sort -u
reading from file falsimentis.pcap, link-type EN10MB (Ethernet)
172.16.42.103
172.16.42.105
172.16.42.107
172.16.42.108
172.16.42.109
172.16.42.2
172.16.42.3
sec504@slingshot:~/labs/falsimentis$
```
## Finding the first packet
To get an estimate when the malicious traffic started, we can examine the first packet that was sent from each compromised host to www1-google-analytics.com (167.172.201.123). This can be done with a for loop as shown here:
```
$ sec504@slingshot:~/labs/falsimentis$ for octet in 2 3 103 105 107 108 109; do TZ=PST7PDT tcpdump -tttt -n -r falsimentis.pcap -c 1 "src host 172.16.42.$octet and dst host 167.172.201.123" 2>/dev/null; done
2020-03-19 09:10:48.693390 IP 172.16.42.2.53699 > 167.172.201.123.8090: Flags [SEW], seq 141186417, win 8192, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 09:38:15.622304 IP 172.16.42.3.52449 > 167.172.201.123.8090: Flags [SEW], seq 966832680, win 8192, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 09:46:11.679708 IP 172.16.42.103.51838 > 167.172.201.123.8090: Flags [S], seq 945749049, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 09:48:39.181576 IP 172.16.42.105.58343 > 167.172.201.123.8090: Flags [S], seq 2308409837, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 09:50:23.886662 IP 172.16.42.107.57932 > 167.172.201.123.8090: Flags [S], seq 1940514557, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 09:55:19.306997 IP 172.16.42.108.61412 > 167.172.201.123.8090: Flags [S], seq 4172553415, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 09:57:04.359504 IP 172.16.42.109.64231 > 167.172.201.123.8090: Flags [S], seq 3275538513, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
sec504@slingshot:~/labs/falsimentis$ 
```
Notice that the timestamps for these packets varies from 9:10 AM to 9:57 AM. However, these timestamps are for packets destined for port 8090, not port 80.
To find the first timestamp for port 80 traffic, modify the previous for loop as shown here:
```
$ sec504@slingshot:~/labs/falsimentis$ for octet in 2 3 103 105 107 108 109; do TZ=PST7PDT tcpdump -tttt -n -r falsimentis.pcap -c 1 "src host 172.16.42.$octet and dst host 167.172.201.123 and dst port 80" 2>/dev/null; done
2020-03-19 10:34:16.505799 IP 172.16.42.103.52458 > 167.172.201.123.80: Flags [S], seq 1388216751, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 10:38:00.315836 IP 172.16.42.105.61182 > 167.172.201.123.80: Flags [S], seq 979163751, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 10:15:36.693484 IP 172.16.42.107.60227 > 167.172.201.123.80: Flags [S], seq 2927374010, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 10:48:35.338023 IP 172.16.42.109.51040 > 167.172.201.123.80: Flags [S], seq 493181052, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
sec504@slingshot:~/labs/falsimentis$
```
We are saving the output from the previous code into a text file "first-talker.txt" for future reference. We used ctrl+D to (end of file) to save the file.
```
$sec504@slingshot:~/labs/falsimentis$ cat > first-talkers.txt
2020-03-19 10:34:16.505799 IP 172.16.42.103.52458 > 167.172.201.123.80: Flags [S], seq 1388216751, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 10:38:00.315836 IP 172.16.42.105.61182 > 167.172.201.123.80: Flags [S], seq 979163751, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 10:15:36.693484 IP 172.16.42.107.60227 > 167.172.201.123.80: Flags [S], seq 2927374010, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
2020-03-19 10:48:35.338023 IP 172.16.42.109.51040 > 167.172.201.123.80: Flags [S], seq 493181052, win 64240, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0
```
Using the awk commmand to extract and print the second and fourth fields from each line in the "first-talkers.txt" file.
```
$ sec504@slingshot:~/labs/falsimentis$ awk '{print $2, $4}' first-talkers.txt
10:34:16.505799 172.16.42.103.52458
10:38:00.315836 172.16.42.105.61182
10:15:36.693484 172.16.42.107.60227
10:48:35.338023 172.16.42.109.51040
```
This command extracts and prints the second and fourth fields from each line in "first-talkers.txt" using AWK and then sorts the output.
```
$ sec504@slingshot:~/labs/falsimentis$ awk '{print $2, $4}' first-talkers.txt | sort
10:15:36.693484 172.16.42.107.60227
10:34:16.505799 172.16.42.103.52458
10:38:00.315836 172.16.42.105.61182
10:48:35.338023 172.16.42.109.51040
sec504@slingshot:~/labs/falsimentis$ 
```
The following iterates over a list of octets (2, 3, 103, 105, 107, 108, 109) and, for each, uses tcpdump to capture and display the timestamp, source, and destination information for one packet where the source IP is "172.16.42.$octet" and the destination is not "167.172.201.123". The -tttt option formats the output with a human-readable timestamp. Any error messages are redirected to /dev/null.
```
$ sec504@slingshot:~/labs/falsimentis$ for octet in 2 3 103 105 107 108 109; do TZ=PST7PDT tcpdump -tttt -n -r falsimentis.pcap -c 1 "src host 172.16.42.$octet and not dst host 167.172.201.123" 2>/dev/null; done
2020-03-19 01:14:42.597200 IP 172.16.42.2.54966 > 172.16.42.10.53: 58959+ [1au] A? incoming.telemetry.mozilla.org. (59)
2020-03-19 01:14:40.419223 IP 172.16.42.3.445 > 172.16.42.108.64548: Flags [.], seq 150858149:150858150, ack 500806940, win 2051, length 1
2020-03-19 01:14:45.241727 IP 172.16.42.103.50441 > 45.76.171.86.80: Flags [.], seq 3621903950:3621903951, ack 2278422879, win 2050, length 1: HTTP
2020-03-19 01:14:40.979538 IP 172.16.42.105.53657 > 172.16.42.20.80: Flags [F.], seq 152144585, ack 1461625225, win 2050, length 0
2020-03-19 01:14:40.009560 IP 172.16.42.107.61578 > 74.125.195.189.443: UDP, length 28
2020-03-19 01:14:39.748124 IP 172.16.42.108.64654 > 74.125.195.188.5228: Flags [.], seq 1252535096:1252535097, ack 3660398813, win 256, length 1
2020-03-19 01:14:46.903396 IP 172.16.42.109.51386 > 172.16.42.3.445: Flags [.], seq 2674162742:2674162743, ack 3112571685, win 2049, length 1
sec504@slingshot:~/labs/falsimentis$
```

# Questions
## What systems are likely compromised in the organization?

Based on the provided information, it appears that the systems with the IP addresses 172.16.42.103, 172.16.42.105, 172.16.42.107, 172.16.42.108, and 172.16.42.109 have engaged in suspicious or potentially malicious activities. These activities include making repeated requests to the domain www1-google-analytics.com (with the IP address 167.172.201.123) and exhibiting beacon-like behavior.

Given this information, these systems could potentially be compromised in the organization. Further investigation and analysis of the network traffic, system logs, and potentially affected systems are recommended to assess the extent of the compromise and to implement appropriate remediation measures.

## When did the threat actors begin the attack?
To determine when the threat actors began the attack, we can look at the timestamps of the first packets sent from the compromised hosts to www1-google-analytics.com (167.172.201.123). The timestamps of the initial packets from each compromised host can provide an estimate of when the attack started.

From the timestamps of the first packets sent to www1-google-analytics.com on port 80 are as follows:

172.16.42.103: 2020-03-19 10:34:16.505799
172.16.42.105: 2020-03-19 10:38:00.315836
172.16.42.107: 2020-03-19 10:15:36.693484
172.16.42.109: 2020-03-19 10:48:35.338023

These timestamps indicate that the attack started around 10:15 AM to 10:48 AM on March 19, 2020. It's important to note that these times are approximate, and further analysis may be needed to refine the timeline and gather additional details about the attack.

## What host(s) are the threat actors using for command and control (C2)?
Threat actors might use a specific server or IP address as a command and control server to communicate with compromised systems. In this case, the IP address 167.172.201.123 is associated with www1-google-analytics.com, which is unusual since Google Analytics is a legitimate service and should not be used for command and control.

Further investigation, network analysis, and examination of additional logs may be necessary to identify the actual host or server used for command and control activities. This may involve analyzing network traffic patterns, DNS requests, and any other indicators of compromise to trace the communication channels used by the threat actors.
