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
Next, continue your preprocessing analysis with the Linux strings utility. Extract the ASCII, 16-bit little endian, and 16-bit big endian strings from the memory image with the three commands shown here.
```
(vol) sec504@slingshot:~/labs/falsimentis$ strings FM-TETRIS.mem > fm-tetris.strings-asc.txt
(vol) sec504@slingshot:~/labs/falsimentis$ strings -e l FM-TETRIS.mem > fm-tetris.strings-unile.txt
(vol) sec504@slingshot:~/labs/falsimentis$ strings -e b FM-TETRIS.mem > fm-tetris.strings-unibe.txt
```
