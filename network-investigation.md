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

## Getting started

sec504@slingshot:~$ cd ~/labs/falsimentis/
sec504@slingshot:~/labs/falsimentis$ ls -l access.log
-rw-r--r-- 1 sec504 sec504 25915052 Aug 12  2021 access.log
sec504@slingshot:~/labs/falsimentis$ wc -l access.log 
177456 access.log
sec504@slingshot:~/labs/falsimentis$ head access.log 
1584606106.376     71 172.16.42.108 TAG_NONE/200 0 CONNECT 151.101.197.209:443 - ORIGINAL_DST/151.101.197.209 -
1584606106.453     69 172.16.42.108 TCP_MISS/200 216782 GET https://secure.img1-fg.wfcdn.com/im/33758501/resize-h630-w1200%5Ecompr-r85/3949/39499404/.jpg - ORIGINAL_DST/151.101.197.209 image/webp
1584606106.494     14 172.16.42.108 TCP_MISS/200 1176 GET https://secure.img1-fg.wfcdn.com/favicon.ico - ORIGINAL_DST/151.101.197.209 image/x-icon
1584606107.926     58 172.16.42.105 TAG_NONE/200 0 CONNECT 209.73.190.12:443 - ORIGINAL_DST/209.73.190.12 -
1584606107.961     24 172.16.42.105 TCP_MISS/200 3157 GET https://s.yimg.com/rz/l/favicon.ico - ORIGINAL_DST/209.73.190.12 image/vnd.microsoft.icon
1584606107.963    160 172.16.42.105 TAG_NONE/200 0 CONNECT 98.136.144.138:443 - ORIGINAL_DST/98.136.144.138 -
1584606108.045     77 172.16.42.105 TCP_MISS/200 3823 GET https://search.yahoo.com/opensearch.xml - ORIGINAL_DST/98.136.144.138 application/opensearchdescription+xml
1584606108.048    202 172.16.42.105 TAG_NONE/200 0 CONNECT 98.138.219.231:443 - ORIGINAL_DST/98.138.219.231 -
1584606108.173     60 172.16.42.105 TAG_NONE/200 0 CONNECT 209.73.190.12:443 - ORIGINAL_DST/209.73.190.12 -
1584606108.200    148 172.16.42.105 TAG_NONE/200 0 CONNECT 98.136.144.138:443 - ORIGINAL_DST/98.136.144.138 -

sec504@slingshot:~/labs/falsimentis$ grep midnitemeerkats access.log
1584648356.572    175 172.16.42.107 TCP_MISS/301 671 GET http://www.midnitemeerkats.com/note - ORIGINAL_DST/69.163.156.144 text/html
1584648359.613   2018 172.16.42.107 TCP_MISS/301 461 GET https://www.midnitemeerkats.com/note - ORIGINAL_DST/69.163.156.144 text/html
1584648360.761    569 172.16.42.107 TCP_MISS/200 4404 GET https://midnitemeerkats.com/note/ - ORIGINAL_DST/69.163.156.144 text/html
1584648360.983     51 172.16.42.107 TCP_MISS/200 1873 GET https://midnitemeerkats.com/wp-content/plugins/memberpress/css/ui/theme.css? - ORIGINAL_DST/69.163.156.144 text/css
sec504@slingshot:~/labs/falsimentis$ 

sec504@slingshot:~/labs/falsimentis$ awk '/midnitemeerkats/ {print $1, $3, $7}' access.log
1584648356.572 172.16.42.107 http://www.midnitemeerkats.com/note
1584648359.613 172.16.42.107 https://www.midnitemeerkats.com/note
1584648360.761 172.16.42.107 https://midnitemeerkats.com/note/
1584648360.983 172.16.42.107 https://midnitemeerkats.com/wp-content/plugins/memberpress/css/ui/theme.css?
sec504@slingshot:~/labs/falsimentis$ 





