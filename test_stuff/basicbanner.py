#!/usr/bin/python
import socket
import sys
import os

delay = 1
#grab the banner
def grab_banner(ip_address,port):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(delay)
  try:
    s.connect((ip_address,port))
    banner= "unknown"
    try:
      banner = s.recv(1024)
      print port + ':' + banner
    except:
       print port + ':' + banner
    print " "
  except socket.timeout:
    print "Socket Timeout"
    s.close()
  except:
   return
def checkVulns(banner):
  if len(sys.argv) >=2:
    filename = sys.argv[1]
    for line in filename.readlines():
      line = line.strip('\n')
      if banner in line:
        print "%s is vulnerable" %banner
      else:
        print "%s is not vulnerable"
def main():
  portList = [21,22,25,80,110]

  for port in portList:
    ip_address = 'scanme.nmap.org'
    grab_banner(ip_address,port)
    
if __name__ == '__main__':
  main()