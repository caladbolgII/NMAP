# NMAP
298

EEE 298 MP NMAP. accepts arguments using argparse instead of getopt


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

Ports List CSV
http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml


#### Functions
tcp_scan(ip_addr, port, delay) 
- scan for open/filtered/closed ports using a dictionary for common ports
Inputs: 
ip_addr - array
port - array
delay - number
Tested with:
scanme.nmap.org
Comments:
Done! Need threading. Also better dictionary for service names.
Further testing needed.

tcp_scan_banner(ip_addr, port, delay)
- same as tcp_scan, but try to find banner from port then use dictionary if cannot
Inputs
ip_addr - array
port - array
delay - number
Tested with:
scanme.nmap.org
Comments:
Done! Need threading. Also better dictionary for service names.
Further testing needed.

udp_scan(ip_addr, port, delay)
inputs: 
ip_addr - array
port - array
delay - number
- scan for open/filtered/closed ports with udp packets

os_detect()


