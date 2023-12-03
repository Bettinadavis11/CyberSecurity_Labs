# Scenario
The victim is Falsimentis, a small (fictitious) corporation based in Los Angeles, California, that produces artificial intelligence hardware and software. On Thursday the CEO decided to take the employees out to lunch. The CEO recalls locking their screen and leaving for lunch around 11:50 AM. Returning from lunch around 1:05 PM, the CEO noticed their computer had rebooted. After logging on, the CEO saw the following:

"C:\Users\betti\OneDrive\Desktop\Slingshot-H02-SEC504-2023-12-02-19-34-11.png"

The message is a ransom note from a group of threat actors calling themselves the Midnite Meerkats. The note states that the Midnite Meerkats have control of the victim's systems, and unless the victim pays the ransom within 24 hours, the victim's files will be deleted. The URL that contains the ransom note is https://midnitemeerkats.com/note/.

The CEO contacted the system administrator, who collected various pieces of evidence. The system administrator was able to collect a packet capture of the internal network traffic that Falsimentis was recording for an upcoming audit by one of their large customers. The system administrator was also able to collect logs from a Squid proxy.

## Timelines

   * The CEO locked their workstation and left for lunch at around 11:50 AM.
   * The CEO returned from lunch and logged on to their workstation at around 1:05 PM.
   * The ransom note popped up after the CEO logged on.
   * The ransom note is hosted at https://midnitemeerkats.com/note/
   * The note states the victim has 24 hours to pay, or their files will be deleted.
   * Compromised systems
       * 172.16.42.107 (FM-CEO)

         


