# Scenario:
Tamra Tidmas, Falsimentis' lead IR analyst, received a support desk ticket about a ransom note. An employee received an email with a link to a site featuring the same video as the ransom note. Suspecting a connection, the support team escalated to the IR team, leading Tamra to image the employee's workstation memory.
One common investigative practice is to preprocess evidence, saving the results to text files so that multiple searches through it are faster. Since you're analyzing memory images, this means running Volatility commands and saving the output.
### Preprocessing with Volatility:
One common investigative practice is to preprocess evidence, saving the results to text files so that multiple searches through it are faster. Since you're analyzing memory images, this means running Volatility commands and saving the output.
```
sec504@slingshot:~/labs/falsimentis$ vol -q -f FM-TETRIS.mem windows.netscan.NetScan > fm-tetris.windows.netscan.NetScan.txt
sec504@slingshot:~/labs/falsimentis$ vol -q -f FM-TETRIS.mem windows.pstree.PsTree > fm-tetris.windows.pstree.PsTree.txt
sec504@slingshot:~/labs/falsimentis$ vol -q -f FM-TETRIS.mem windows.pslist.PsList > fm-tetris.windows.pslist.PsList.txt
sec504@slingshot:~/labs/falsimentis$ vol -q -f FM-TETRIS.mem windows.cmdline.CmdLine > fm-tetris.windows.cmdline.CmdLine.txt
sec504@slingshot:~/labs/falsimentis$ vol -q -f FM-TETRIS.mem windows.filescan.FileScan > fm-tetris.windows.filescan.FileScan.txt
sec504@slingshot:~/labs/falsimentis$ vol -q -f FM-TETRIS.mem windows.dlllist.DllList > fm-tetris.windows.dlllist.DllList.txt
```
Instead of running all of these commands individually, you could opt to run them all at once using a shell loop with the following command: 
```
for plugin in windows.netscan.NetScan windows.pstree.PsTree windows.pslist.PsList windows.cmdline.CmdLine windows.filescan.FileScan windows.dlllist.DllList; do vol -q -f FM-TETRIS.mem $plugin > fm-tetris.$plugin.txt; done
```
### Preprocessing with Strings
Next, continue your preprocessing analysis with the Linux strings utility. Extract the ASCII, 16-bit little endian, and 16-bit big endian strings from the memory image with the three commands shown here.The reason why we are doing this is because the command strings doesn't know it is dealing with a memory campture but it does is collects any plain strings in any file that you specify.
```
(vol) sec504@slingshot:~/labs/falsimentis$ strings FM-TETRIS.mem > fm-tetris.strings-asc.txt
(vol) sec504@slingshot:~/labs/falsimentis$ strings -e l FM-TETRIS.mem > fm-tetris.strings-unile.txt
(vol) sec504@slingshot:~/labs/falsimentis$ strings -e b FM-TETRIS.mem > fm-tetris.strings-unibe.txt
```
### Examining Network Connections
Lets scan the content of the file "fm-tetris.windows.netscan.NetScan.txt" for lines that contain the IP address "167.172.201.123" and displays those lines as output.
```
sec504@slingshot:~/labs/falsimentis$ grep 167.172.201.123 fm-tetris.windows.netscan.NetScan.txt
0xb08a4da8  TCPv4   172.16.42.103   55418   167.172.201.123 80  CLOSED  5736    analytics.exe   -
0xc18db2b8  TCPv4   172.16.42.103   55419   167.172.201.123 80  ESTABLISHED 5736    analytics.exe   -
```
Notice the name of the process that connected to the suspicious IP address, analytics.exe with process ID 5736. Given that the domain was www1-google-analytics.com, the name analytics.exe seems like it would be a natural fit.
Next, see if analytics.exe is communicating with any other sites using grep again, this time by searching for the process name rather than IP address in the windows.netscan.NetScan plugin output, as shown here.
```
sec504@slingshot:~/labs/falsimentis$ grep 'analytics.exe' fm-tetris.windows.netscan.NetScan.txt
0xa69ae7a8	UDPv4	0.0.0.0	0	*	0		5736	analytics.exe	2020-03-19 20:16:13.000000 
0xa69ae7a8	UDPv6	::	0	*	0		5736	analytics.exe	2020-03-19 20:16:13.000000 
0xa79bca58	UDPv4	0.0.0.0	0	*	0		5736	analytics.exe	2020-03-19 20:16:18.000000 
0xa79bca58	UDPv6	::	0	*	0		5736	analytics.exe	2020-03-19 20:16:18.000000 
0xb08a4da8	TCPv4	172.16.42.103	55418	167.172.201.123	80	CLOSED	5736	analytics.exe	-
0xc18db2b8	TCPv4	172.16.42.103	55419	167.172.201.123	80	ESTABLISHED	5736	analytics.exe	-
```
### Examining Processes
To analyze running processes from a memory image, use the windows.pslist.PsList and windows.pstree.PsTree plugins. The latter is beneficial for visualizing parent-child relationships. Use grep to filter the output, searching for "analytics.exe" with context lines for clarity.
```
sec504@slingshot:~/labs/falsimentis$ grep -C 3 'analytics.exe' fm-tetris.windows.pstree.PsTree.txt
*** 8016	4952	ONENOTE.EXE	0xa0868bc0	22	-	1	False	2020-03-19 14:52:51.000000 	N/A
**** 5568	8016	bJKRJiSAnPkf.e	0x8b147bc0	0	-	1	False	2020-03-19 17:33:03.000000 	2020-03-19 18:45:36.000000 
**** 4452	8016	cmd.exe	0x972fdbc0	0	-	1	False	2020-03-19 17:34:06.000000 	2020-03-19 17:34:11.000000 
***** 2532	4452	analytics.exe	0x8b2e2bc0	1	-	1	False	2020-03-19 17:34:09.000000 	N/A
****** 5736	2532	analytics.exe	0x8b1fb100	3	-	1	False	2020-03-19 17:34:10.000000 	N/A
******* 5804	5736	cmd.exe	0xa795bbc0	0	-	1	False	2020-03-19 18:08:06.000000 	2020-03-19 18:08:06.000000 
*** 164	4952	BvSsh.exe	0x8b3c1380	5	-	1	False	2020-03-19 07:05:40.000000 	N/A
*** 4444	4952	cmd.exe	0x8a216440	0	-	1	False	2020-03-19 07:04:37.000000 	2020-03-19 17:57:00.000000 
sec504@slingshot:~/labs/falsimentis$ 
```
This is an odd-looking process tree. ONENOTE.EXE (process ID 8016) spawned cmd.exe (process ID 4452). This cmd.exe spawned analytics.exe (process ID 2532). This copy of analytics spawned another copy of analytics.exe (process ID 5736). The second analytics.exe spawned another cmd.exe (process ID 5804). ONENOTE.EXE also spawned a random-looking process named bJKRJiSAnPkf.e (process ID 5568).
```
sec504@slingshot:~/labs/falsimentis$ grep 'analytics.exe' fm-tetris.windows.filescan.FileScan.txt
0x944d7940	\Windows\System32\analytics.exe	128
0xc18c5348	\Windows\System32\analytics.exe	128
sec504@slingshot:~/labs/falsimentis$ 
```
### Examining file objects
Next let's examine file objects to see if there is anything else useful for our analysis. Use the grep command to search the output of the windows.filescan.FileScan plugin, as shown here.
Reviewing the output, it appears analytics.exe is stored in the \Windows\System32 directory. This information can be useful when building indicators (signatures) that the malware may be installed on a system.
Searching for the string bJKRJiSAnPkf.e yields no results.
```
sec504@slingshot:~/labs/falsimentis$ grep 'bJKRJiSAnPkf.e' fm-tetris.windows.filescan.FileScan.txt
sec504@slingshot:~/labs/falsimentis$
```
### Examining Loaded DLLs
Next, let's take a look at loaded DLLs and command lines for the processes of interest (analytics.exe and bJKRJiSAnPkf.e). The windows.dlllist.DllList plugin can show this information. Use the grep command to show 5 lines of context before and after each string match for analytics.exe, as shown here.
```
sec504@slingshot:~/labs/falsimentis$ grep -C 5 'analytics.exe' fm-tetris.windows.dlllist.DllList.txt
3576	mmc.exe	0x68550000	0x2c000	dnscmmc.dll	C:\Windows\System32\dnscmmc.dll2020-03-19 15:36:36.000000 	Disabled
3576	mmc.exe	0x5c2e0000	0x80000	-	-	2020-03-19 15:36:36.000000 	Disabled
3576	mmc.exe	0x567d0000	0x91000	Microsoft.ManagementConsole.ni.dll	C:\Windows\assembly\NativeImages_v4.0.30319_32\Microsoft.Mff1be75b#\047b6fc35ce426a3433c6cec552162c4\Microsoft.ManagementConsole.ni.dll	2020-03-19 15:36:36.000000 	Disabled
3576	mmc.exe	0x6e180000	0xd000	-	-	2020-03-19 15:36:36.000000 	Disabled
3576	mmc.exe	0x6da90000	0x166000	-	-	2020-03-19 15:36:36.000000 	Disabled
2532	analytics.exe	0x0	0x12d1c800			5934-03-13 19:34:15.000000 	Disabled
2532	analytics.exe	0x0	0x0			N/A	Disabled
5736	analytics.exe	-	-	-	-	-	Disabled
4900	firefox.exe	0x0	0x0			N/A	Disabled
884	audiodg.exe	-	-	-	-	-	Disabled
5080	smartscreen.ex	-	-	-	-	-	Disabled
1160	backgroundTask	0xc8c7d606	0x745fd27b	씢爁剆兲䅮坏簶浳笺瀢㨢笢停ᇰ∄就㨢7㍋尬㈢à紲䱽㜀！ôɘ⸰尰瀢㌀Ƹ≜半΅ꉡb戴氀獣௃≜ɹĉ㔱㐸࿘㈹㤲㜱ƨŁ㘷㠵	ｹAｯǬǓ	-	Disabled
1160	backgroundTask	0x595b52	0xba01e4b9	璠፾܀፹᠔ȀȘ羈꾷ဆಚ㠢ԀȀ묀＀		1669-09-06 12:24:34.000000 	Disabled
sec504@slingshot:~/labs/falsimentis$ 
sec504@slingshot:~/labs/falsimentis$ 
```
Unfortunately, Volatility isn't able to enumerate DLL information for the analytics.exe process. There are different reasons for this, such as the relevant memory pages being swapped out to disk, smear issues (problems caused because the memory is changing while it is being captured), and so on.

### Examining Command Lines
Next, let's check for any command line details associated with the analytics.exe process using grep, as shown here.
```
sec504@slingshot:~/labs/falsimentis$ grep analytics.exe fm-tetris.windows.cmdline.CmdLine.txt
2532	analytics.exe	
5736	analytics.exe	Required memory at 0x1531604 is inaccessible (swapped)
sec504@slingshot:~/labs/falsimentis$
```
The memory capture does not indicate any command line information for other process, though the child process reports inaccessible memory. This is common for memory analysis as saw earlier with the windows.dlllist.DllList plugin; while memory analysis is useful for incident response, it is not always a comprehensive source of information.

### Examining Strings
Using a tool like Volatility allows you to extract and interpret information from memory images in an accessible format. Sometimes the ability to use such tools is not available, and you must rely on lower resolution techniques. One popular approach is to use the strings utility.

### Searching for analytics.exe
Since the Midnite Meerkats appear to be using a program named analytics.exe let's search through the (previously-extracted) strings to see if there is anything else relevant.
The command searches for lines containing "analytics.exe" in the file "fm-tetris.windows.cmdline.CmdLine.txt" using grep. We will get a lot of results, but we can sort them out on our next step.
```
sec504@slingshot:~/labs/falsimentis$ grep analytics.exe fm-tetris.windows.cmdline.CmdLine.txt
2532	analytics.exe	
5736	analytics.exe	Required memory at 0x1531604 is inaccessible (swapped)
sec504@slingshot:~/labs/falsimentis$ grep -i 'analytics.exe' fm-tetris.strings-*.txt
fm-tetris.strings-asc.txt:analytics.exe.manifest
fm-tetris.strings-asc.txt:analytics.exe.manifest
fm-tetris.strings-asc.txt:analytics.exe
fm-tetris.strings-asc.txt:dows\system32\analytics.exe" 
fm-tetris.strings-asc.txt:analytics.exe
fm-tetris.strings-asc.txt:DxgKanalytics.exe
fm-tetris.strings-asc.txt:analytics.exe
fm-tetris.strings-asc.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-asc.txt:DxgKanalytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\Device\HarddiskVolume2\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:\Device\HarddiskVolume2\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:\Device\HarddiskVolume2\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exeal
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:\Device\HarddiskVolume2\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:ANALYTICS.EXE
fm-tetris.strings-unile.txt:C:\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:ANALYTICS.EXE
fm-tetris.strings-unile.txt:analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:indows\system32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\Device\HarddiskVolume2\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:indows\system32\analytics.exe
fm-tetris.strings-unile.txt:indows\system32\analytics.exe
fm-tetris.strings-unile.txt:\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe?6844055
fm-tetris.strings-unile.txt:C:\Windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\Device\HarddiskVolume2\Windows\System32\analytics.exe
fm-tetris.strings-unile.txt:\device\harddiskvolume2\windows\system32\analytics.exe
fm-tetris.strings-unile.txt:\Device\HarddiskVolume2\Windows\System32\analytics.exe
sec504@slingshot:~/labs/falsimentis$
```
The command uses grep to search for lines containing the case-insensitive string 'windows\system32\analytics' in files matching the pattern 'fm-tetris.strings-*.txt'. The -i option ignores case sensitivity, and the -h option suppresses the display of filenames. The results are then sorted and duplicate lines are removed (sort -u). The displayed output indicates a line containing the specified string, referring to a command in a batch file ('analyticsbackup.bat') located in 'C:\Windows\System32'.
```
sec504@slingshot:~/labs/falsimentis$ grep -i -h 'windows\\system32\\analytics' fm-tetris.strings-*.txt | sort -u
      <Command>C:\Windows\System32\analyticsbackup.bat</Command>
C:\Windows\system32\analytics.exe
C:\Windows\System32\analytics.exe
C:\Windows\system32\analytics.exe?6844055
C:\Windows\system32\AnalyticsInstaller.exe
\device\harddiskvolume2\windows\system32\analytics.exe
\Device\HarddiskVolume2\Windows\System32\analytics.exe
\device\harddiskvolume2\windows\system32\analyticsinstaller.exe
\Windows\System32\analytics.exe
sec504@slingshot:~/labs/falsimentis$
```
### Searching for bJKRJiSAnPkF.e
Now perform the same type of search for the oddly named executable bJKRJiSAnPkf.e without the .e extension (to increase the chance of finding related files):
```
sec504@slingshot:~/labs/falsimentis$ grep -i -h bJKRJiSAnPkf fm-tetris.strings-*.txt | sort -u
	bbJKRJiSAnPkf.
bJKRJiSAnPkf
bJKRJiSAnPkf.e
BJKRJISANPKF.EXE
bJKRJiSAnPkf.exe.lo
C:\Users\JCHADW~1\AppData\Local\Temp\bJKRJiSAnPkf.exe
\Device\HarddiskVolume2\Users\JCHADW~1\AppData\Local\Temp\bJKRJiSAnPkf.exe
\device\harddiskvolume2\users\jchadwick\appdata\local\temp\bjkrjisanpkf.exe
sec504@slingshot:~/labs/falsimentis$
```
# Questions
### What is the name of the process making connections to http://www1-google-analytics.com?
    The process making connections to http://www1-google-analytics.com is identified as analytics.exe.
  
### Where is the process located on the file system?
    The process "analytics.exe" is located in the following directories:
    C:\Windows\System32\analytics.exe
    \Device\HarddiskVolume2\Windows\System32\analytics.exe
    C:\Windows\system32\analytics.exe

### What additional suspicious processes are there on the system?
    Based on the provided information, the following suspicious processes are identified:
    bJKRJiSAnPkf.e
    analyticsbackup.bat
    AnalyticsInstaller.exe

### Identify an additional server used by the Midnite Meerkats
    An additional server used by the Midnite Meerkats is www1-google-analytics.com. This domain may be involved in the network activity of interest and could be part of a 
    potentially malicious infrastructure.
