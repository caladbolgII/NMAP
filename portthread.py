import threading
from Queue import Queue
import time
import socket

print_lock = threading.Lock()



target = 'scanme.nmap.org'
#ip = socket.gethostbyname(target)
delay = 3



def portscan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(delay)
    try:
        con = s.connect((target,port))
        with print_lock:
            print('port',port)
      
        con.close()
    except socket.timeout:
        print "Socket timeout on " + str(port)
    except (KeyboardInterrupt, SystemExit):
        s.close()
    except:
        pass


# The threader thread pulls an worker from the queue and processes it
def threader():
    while True:
        # gets an worker from the queue
        worker = q.get()

        # Run the example job with the avail worker in queue (thread)
        portscan(worker)

        # completed with the job
        q.task_done()


# Create the queue and threader 
q = Queue()

# how many threads are we going to allow for
for x in range(30):
     t = threading.Thread(target=threader)

     # classifying as a daemon, so they will die when the main dies
     t.daemon = True

     # begins, must come after daemon definition
     t.start()


start = time.time()

# 100 jobs assigned.
try:
    for worker in range(1,100):
        q.put(worker)
    # wait until the thread terminates.
    q.join()
except (KeyboardInterrupt, SystemExit):
    print "You pressed Ctrl+C"
except:
    raise

