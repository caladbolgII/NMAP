#print_lock = threading.Lock()

import threading
from Queue import Queue
import time
import socket
import sys
    
q = Queue()
delay = 10
ip_addr = "scanme.nmap.org"


print_lock = threading.RLock()

def grab(conn):
    try:
        #conn.send('OPEN \r\n')
        ret = conn.recv(1024)
        print '[+]' + str(ret)
    except Exception, e:
        print '[-] Unable to grab any information: ' + str(e)

def grab_25(conn, smtp_addr):
    try:
        msg_send = "HELO " + smtp_addr + "\r\n"
        conn.send(msg_send)
        ret = conn.recv(1024)
        print '[+]' + str(ret)
    except Exception, e:
        print '[-] Unable to grab any information: ' + str(e)
        
        
def grab_80(conn):
    try:
        conn.send('HEAD / HTTP/1.0\r\n\r\n')
        ret = conn.recv(1024)
        if (str(ret) == "Protocol mismatch."):
            conn.send('HEAD / HTTP/1.1\r\n\r\n')
            ret = conn.recv(1024)
            
        print '[+]' + str(ret)
    except Exception, e:
        print '[-] Unable to grab any information: ' + str(e)
    

def portscan_tcp(ip_addr, port, delay):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(delay)
    open = False
    conn = ""
    try:
        if (port == 25):
            smtp_addr = "smtp." + ip_addr
            print smtp_addr
            conn = s.connect((smtp_addr,port))
        else:
            conn= s.connect((ip_addr,port))
        with print_lock:
            print "Port " +  str(port) + ": Open"
            open = True
    except socket.timeout:
        print "Socket timeout on " + str(port)
    except (KeyboardInterrupt, SystemExit):
        s.close()
        sys.exit()
    except:
       
        print "Port " +  str(port) + ": Closed"
        pass

    # Banner Grabbing
    if (open):
        if (port == 80):
            grab_80(s)
        elif (port == 25):
            grab_25(s, smtp_addr)
        else:
            grab(s)
        s.close()
        
# The threader thread pulls an worker from the queue and processes it
def threader():
    while True:
        # gets an worker from the queue
        worker = q.get()

        # Run the example job with the avail worker in queue (thread)
        portscan_tcp(ip_addr, worker, delay)

        # completed with the job
        q.task_done()
        
    
    
if __name__ == '__main__':

    # Create the queue and threader 

    #ip_addr = raw_input('Enter host to scan: ')
    
    # how many threads are we going to allow for
    for x in range(30):
         t = threading.Thread(target=threader)
    
         # classifying as a daemon, so they will die when the main dies
         t.daemon = True
    
         # begins, must come after daemon definition
         t.start()

    # 100 jobs assigned.
    try:
        for port in range(1,100):
            q.put(port)
        # wait until the thread terminates.
        q.join()
    except (KeyboardInterrupt, SystemExit):
        print "You pressed Ctrl+C"
    except:
        raise

