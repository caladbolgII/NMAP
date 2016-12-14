#!/usr/bin/env python
from socket import * 
import sys

if __name__ == '__main__':
    target = raw_input('Enter host to scan: ')
    targetIP = gethostbyname(target)
    print 'Starting scan on host ', targetIP

    #scan reserved ports
    for i in range(20, 1025):
        s = socket(AF_INET, SOCK_STREAM)

        try:
           
            result = s.connect_ex((targetIP, i))
            if(result == 0) :
                print 'Port %d: OPEN' % (i,)
            else:
                print 'Port %d: CLOSED' % (i,)
        except socket.timeout:
            print 'Socket Timeout on ', i
            s.close()
        except socket.gaierror:
            print 'Hostname could not be resolved. Exiting'
            sys.exit()
        except socket.error:
            print "Couldn't connect to server"
            sys.exit()
        except (KeyboardInterrupt, SystemExit):
            s.close()

        
        s.close()
