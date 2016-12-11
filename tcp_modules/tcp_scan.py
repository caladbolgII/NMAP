import threading
from Queue import Queue
import time
import socket
import errno
from socket import error as socket_error
import sys
import csv
from tabulate import tabulate
import logging

logging.basicConfig(level=logging.DEBUG,
					format='%(asctime)s (%(threadName)-2s) %(message)s')

def tcp_scan(ip_addr, port, delay):
    """
        Spec: default is the 1000 ports that is being used by NMAP

        Def:
        scan for open/filtered/closed ports using a dictionary for common ports

        inputs: 
        ip_addr - array
        port - array
        delay - number
    """
    print "\n\n\n"
    # Load TCP ports and names dictionary
    dict_tcp = {}
    with open('./files/tcp_list.csv') as csvfile:
        tcp_list = csv.reader(csvfile)
        for row in tcp_list:
            # parsing dictionary
            if (dict_tcp.has_key(row[1]) == False):
                dict_tcp[row[1]] = row[0]
    
    # Going through all stated IP Addresses
    results_list = []
    closed_ports = 0
    first_index = 0
    for ip_num in ip_addr:
        results_list.append([])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(delay)

        # Going through all stated ports for each IP address
        for port_num in port:
            port_str = "{}/tcp".format(port_num)
            portserv = ""
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(delay)
                con = s.connect((ip_num,port_num))
                logging.debug("Port {}: Open".format(str(port_num)))
                s.close()

                try:
                    portserv = socket.getservbyport(port_num, "tcp")
                except socket.error:                    
                    if (dict_tcp.has_key(str(port_num)) == True):
                        portserv = dict_tcp[str(port_num)]
                    else:
                        portserv = "unknown"

                results_list[first_index].append([port_str, "open", portserv])
                #results_list[first_index].append([port_str, "open", dict_tcp[str(port_num)]])
            except socket.timeout:
                s.close()
                logging.debug("Socket timeout on {}".format(str(port_num)))
                try:
                    portserv = socket.getservbyport(port_num, "tcp")
                except socket.error:                    
                    if (dict_tcp.has_key(str(port_num)) == True):
                        portserv = dict_tcp[str(port_num)]
                    else:
                        portserv = "unknown"
                results_list[first_index].append([port_str, "filtered", socket.getservbyport(port_num, "tcp")])
                #results_list[first_index].append([port_str, "filtered", dict_tcp[str(port_num)]])
            except socket.error, exc:
                logging.debug("Socket error on {}: {}".format(str(port_num), exc))
                s.close()
                #logging.debug("Socket error on {}".format(str(port_num)))
                closed_ports = closed_ports + 1
            except (KeyboardInterrupt, SystemExit):
                print ("The program was exited.")
                s.close()
                sys.exit()
            except:
                s.close()
                print("Port {}: Unexpected error: {}".format(port_num, sys.exc_info()[0]))
                raise


        # Increment for results table
        first_index = first_index + 1
    
   
    # Printing Results
    second_index = 0
    for ip_num in ip_addr:
        print ("Scan report for: {} ({})".format(socket.getfqdn(ip_num), socket.gethostbyname(ip_num)))
        print ("Not shown: {} closed ports".format(closed_ports))
        print tabulate(results_list[second_index], headers=["PORT", "STATE", "SERVICE"])
        second_index = second_index + 1

if __name__ == '__main__':
    #ip_addr = "scanme.nmap.org"
    #ip_addr = raw_input('Enter host to scan: ')
    delay = 5
    #port = 22
    ip_addr=["scanme.nmap.org"]
    #port = range(1, 30)
    port = [1,22, 25, 80, 465, 587, 3333, 9929, 31337]
    #port = [22]
    #for i in range(20, 25):
    tcp_scan(ip_addr, port, delay)
