import threading
from Queue import Queue
import time
import socket
import errno
from socket import error as socket_error
import sys
import csv
from tabulate import tabulate

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

    # Load TCP ports and names dictionary
    dict_tcp = {}
    with open('./files/tcp_list.csv') as csvfile:
        tcp_list = csv.reader(csvfile)
        #tcp_list = csv.DictReader(csvfile)
        for row in tcp_list:
            #print row
            # parsing dictionary
            if (dict_tcp.has_key(row[1]) == False):
                dict_tcp[row[1]] = row[0]
                #print tcp_list['22']    
                #print row['']
                #print (row['Service Name'], row['Port Number'], row['Transport Protocol'], row['Description'])

    results_list = []
    results_list.append([])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(delay)
    try:
        con = s.connect((ip_addr,port))
        print "Port " +  str(port) + ": Open"
        s.close()
    except socket.timeout:
        print "Socket timeout on " + str(port)
    except socket_error as serr:
        if serr.errno != errno.ECONNREFUSED:
            print "Filtered port"
        else:
            print "Unknown"
    except (KeyboardInterrupt, SystemExit):
        s.close()
        sys.exit()
    else:
        port_str = "{}/tcp".format(port)
        print port_str
        print dict_tcp[str(port)]
        results_list[0].append([port_str, "open", dict_tcp[str(port)]])
        print "insert banner"

    print tabulate(results_list[0], headers=["PORT", "STATE", "SERVICE"])


if __name__ == '__main__':
    ip_addr = "scanme.nmap.org"
    #ip_addr = raw_input('Enter host to scan: ')
    delay = 1
    port = 22
    #for i in range(20, 25):
    tcp_scan(ip_addr, port, delay)
   
    