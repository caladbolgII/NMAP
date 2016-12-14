#### Specs
Inputs:
- host name e.g. pleni.upd.edu.ph
- ip address e.g. 202.92.128.181
- ip range e.g. 202.92.128.1-254
- network e.g. 202.92.128.0/24

TCP Scanning
- default is the 1000 ports that is being used by NMAP
- specify port e.g. 80
- specify port range e.g. 90-10000

UDP Scanning
- bonus 15%
- at least port 53 and 161

Service Name / Banner Grabbing
- bonus 15%

OS Detection
- bonus 15%

Deadline is December 14 and our CTF will be on the 15th.

https://www.hackthissite.org/
scanme.nmap.org

#### References
http://www.primalsecurity.net/0x1-python-tutorial-port-scanner/
http://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python
http://code.activestate.com/recipes/576690-pyscanlogger-python-port-scan-detector/
http://code.activestate.com/recipes/576690-pyscanlogger-python-port-scan-detector/



#### Working ports
**Windows 10*
w/firewall
-
w/o firewall
port = [135, 139, 445, 902, 912]

**NMAP**
port = [1,22, 25, 80, 264, 465, 587, 1720, 3333, 9929, 31337]
