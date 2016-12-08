#print_lock = threading.Lock()

def portscan_tcp(ip_addr, port, delay):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(delay)
    try:
        con = s.connect((ip_addr,port))
        #with print_lock:
        print('port',port)
      
        con.close()
    except socket.timeout:
        print "Socket timeout on " + str(port)
    except (KeyboardInterrupt, SystemExit):
        s.close()
        sys.exit()
    except:
        pass
    
    
if __name__ == '__main__':
    import threading
    from Queue import Queue
    import time
    import socket
    import sys
    
    ip_addr = raw_input('Enter host to scan: ')
    delay = 1
    for i in range(20, 25):
        portscan_tcp(ip_addr, i, delay)