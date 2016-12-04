#!/usr/bin/python
import socket
import sys
import getopt
import struct
import binascii
import string
import timeit
import time
from collections import deque
import threading
from decimal import *
import random

##############################################################
# arsf = ack valid, reset, syn bit, finish bit receive windows size
# packet 1 0010 = syn bit =1, receive window size 1byte = 1024
# get args and set them to variables


class client(object):

        def __init__(self):
                try:
                        global rcvbuf
                        getcontext().prec = 3
                        rcvbuf = deque()
                        endproc = 0
                        opts, args = getopt.getopt(sys.argv[1:], "f:c:w:i:t:d:r:v", ["help"])
                        self.verbose = 0
                        for opt, arg in opts:
                                if opt == '-f':
                                        self.filename = arg
                                elif opt == '-c':
                                        self.chunksize = arg
                                elif opt == '-w':
                                        self.windowsize = arg
                                elif opt == '-i':
                                        self.server_initseq = arg
                                elif opt == '-t':
                                        self.timeout = arg
                                elif opt == '-d':
                                        self.delay =  arg
                                elif opt == '-r':
                                        self.ADDR, self.PORT = arg.split(':')
                                elif opt == '-v':
                                        self.verbose = 1

                except getopt.GetoptError as err:
                       # print help information and exit:
                        # print str(err) # will print something like "option -a not recognized"
                        print 'Usage: client.py -f <file_number> -c <chunksize> -w <window_size> -i <initial_sequence_number> -t <timeout> -d <delay> -r <addr:port> -v (verbose)'
                        sys.exit(2)
                #convert delay to ms
                self.delay2 = Decimal(self.delay)/Decimal(1000)
                self.chunksize = int(self.chunksize)
                self.windowsize = int(self.windowsize)
                self.initseq = int(40)
                self.server_initseq = int(self.server_initseq)
                self.timeout = int(self.timeout)
                self.delay = int(self.delay)
                self.rcvwindow = self.windowsize*2
                self.ack = int(0)
                self.rwnd = int(1024)
                self.flag = int(2)
                self.seq = int(self.initseq)
                self.cyclelost = 0
                #0b0010 syn bit
                #sequential number 20
                self.seq_expected = 0
                self.datagram = struct.pack('9i 32s',self.initseq,self.ack,self.flag,self.rwnd,self.chunksize,self.windowsize,self.timeout,self.delay,self.server_initseq,self.filename,)
                #print 'Packed Value   :', binascii.hexlify(payload)
                #print 'Packed Value   :', payload
                # Create a UDP socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                #self.sock.settimeout(5000)
                self.sock.setblocking(True)
                self.seqold = 0;
                self.server_address = (self.ADDR, int(self.PORT))
                self.receivedbytescount = 0
                self.datagramcount = 0
                self.duplicate = 0
                self.connect = 1
                self.receive = 0
                self.handshake()
                self.dataremaining = 0

        def handshake(self):
                try:

                    # Send data
                    #print >>sys.stderr, 'sending "%s"' % payload

                    #print "Client seq no: ", self.seq,"Client ack no sent: ", self.ack ,"Server seq no received", self.server_seq,"Server ack received:", self.ack_rcv

                    #VERBOSE


                    while self.connect == 1:
                            self.t0 = time.time()
                            print "Connecting to server at address" , self.ADDR, "Port", self.PORT
                            #print "Sending seq:{} ack:{} flag:{} rwnd:{} chunksize:{} windowsize:{} timeout:{} delay:{} filename:{}".format(self.seq,self.ack,self.flag,self.rwnd,self.chunksize,self.windowsize,self.timeout,self.delay,self.filename)
                            self.sent = self.sock.sendto(self.datagram, self.server_address)
                            print "SYN sent"
                            if self.verbose == 1:
                                    print "Initial Seq number", self.initseq,"ACK number", self.ack
                            # Receive response
                            print 'waiting to receive'

                            self.data, self.server = self.sock.recvfrom(4096)

                            self.server_seq,self.ack_rcv,self.flag_rcv,self.rwnd_rcv,self.chunksize_rcv,self.indowsize_rcv,self.timeout_rcv,self.delay_rcv,self.srv_ini_rcv,self.filename_rcv = struct.unpack('9i 32s', self.data)

                            if self.verbose == 1:
                                    print"Server seq no received", self.server_seq,"Server ack received:", self.ack_rcv


                            self.receivedbytescount = self.receivedbytescount + sys.getsizeof(self.data)

                            if self.flag_rcv == 10:
                                    # received flag is ack

                                    self.ack = self.server_seq+sys.getsizeof(self.filename_rcv)

                                    #ack seq number of sent
                                    self.seq = int(self.initseq+sys.getsizeof(self.filename_rcv))+1

                                    #increment sequence number by ack
                                    self.flag = 8
                                    #flag for syn-ack 1010
                                    #print "Client seq no: ", self.seq,"Client ack no sent: ", self.ack ,"Server seq no received", self.server_seq,"Server ack received:", self.ack_rcv,"Flag", self.flag
                                    self.datagram = struct.pack('9i 32s',self.seq,self.ack,self.flag,self.rwnd,self.chunksize,self.windowsize,self.timeout,self.server_initseq,self.delay,self.filename)
                                    #print "Sending seq:{} ack:{} flag:{} rwnd:{}   chunksize:{} windowsize:{}timeout:{} delay:{} filename:{}".format(self.seq,self.ack,self.flag,self.rwnd,self.chunksize,self.windowsize,self.timeout,self.delay,self.filename)
                                    self.sent = self.sock.sendto(self.datagram, self.server_address)
                                    if self.verbose == 1:
                                            print "Seq number", self.seq,"ACK number", self.ack
                                    print "ACK sent"
                                    self.connect = 0
                                    self.receive = 1
                                    self.fo = open(self.filename, "wb")
                                    print "File " ,self.filename, "created, ready for writing"
                                    self.seq_expected = self.ack
                                    self.chunk_count = 0
                                    self.hsk_done = 1;
                                    print"seq no before incrmeneting for sending", self.seq
                                    self.seq = int(self.seq+sys.getsizeof(self.filename_rcv))
                                    return
                                    break
                            else:
                                    #resend first packet
                                    print "Invalid flag resending SYN packet"
                                    self.sent = self.sock.sendto(self.datagram, self.server_address)
                                    if self.verbose == 1:
                                            print "Seq number", self.seq,"ACK number", self.ack
                except KeyboardInterrupt:

                    print 'errorists win1'
                    sys.exit(2)
                except Exception, e:
                    print type(e)  # Should give you the exception type
                #append file



        def receive_file(self):
                try:
                    while self.receive == 1:
                           global endproc
                           endproc = 0
                           #file receive mode
                           print "Waiting for file packets"
                           self.data, self.server = self.sock.recvfrom(4096)
                           self.chunk_count += 1
                           if (random.uniform(0,1) < 0.1):
                                   self.data = None
                                   print("Packet dropped randomly to simulate packet losses")
                           else:
                                   self.server_seq,self.ack_rcv,self.flag_rcv,self.raw_chunk = struct.unpack('3i %ds' % self.chunksize, self.data)
                                   time.sleep(self.delay2)
                                   self.receivedbytescount = self.receivedbytescount + sys.getsizeof(self.data)
                                   self.datagramcount = self.datagramcount+ 1
                                   if self.verbose == 1:
                                           print"Server seq no received", self.server_seq,"Server ack received:", self.ack_rcv
                                           print "expected",self.seq_expected,"actual",self.server_seq

                                   if self.server_seq == self.seq_expected  :
                                           if self.flag_rcv == 0:

                                                   self.flag = 8
                                                   #print "raw chunk", self.raw_chunk
                                                   self.new = 'A'

                                                   # 0flag for sending in server, ack of client is 8
                                                   if self.hsk_done == 1:# SEQUENCE NUMBER
                                                           self.seq = self.seq
                                                           self.hsk_done = 0
                                                   else:
                                                           self.seq = self.seq+1

                                                   self.ack = self.server_seq+self.chunksize#int(sys.getsizeof(self.raw_chunk))+1
                                                   #ack seq number of sent
                                                   self.raw_chunk = self.raw_chunk.rstrip('\x00')
                                                   rcvbuf.extend(self.raw_chunk)
                                                   self.dataremaining += 1
                                                   self.datagram = struct.pack('3i s',self.seq,self.ack,self.flag,self.new)
                                                   self.seq_expected = self.server_seq+int(sys.getsizeof(self.raw_chunk))+1

                                                   self.sent = self.sock.sendto(self.datagram, self.server_address)
                                                   if self.verbose == 1:
                                                           print "Seq number", self.seq,"ACK number", self.ack
                                                           print "expected new seq", self.seq_expected

                                           elif self.flag_rcv == 1:
						   print "Flag is 1"
                                                   self.flag = 9 # fin ack flag
                                                   # 0flag for sending in server, ack of client is 8
                                                   self.seq = self.seq+1
                                                   #ack seq number of sent

                                                   #strip chunk of excess
                                                   self.ack = self.server_seq+int(sys.getsizeof(self.raw_chunk))+1
                                                   #rcvbuf.extend(self.raw_chunk)
                                                   #self.dataremaining += 1
                                                   self.datagram = struct.pack('3i s',self.seq,self.ack,self.flag,self.new)
                                                   self.sent = self.sock.sendto(self.datagram, self.server_address)
                                                   if self.verbose == 1:
                                                           print "Seq number", self.seq,"ACK number", self.ack
                                                           print "FIN RECEIVED"
                                                   self.t1 = time.time()

                                                   self.total = self.t1-self.t0

                                                   self.unique = self.datagramcount - self.duplicate
                                                   #print "unique",self.unique
                                                   #self.goodput = self.unique / self.total
                                                   print "Transfer done in", self.total, "seconds"
                                                   print "No. of datagrams received:", self.datagramcount
                                                   print "No. of duplicate datagrams received:", self.duplicate
                                                   print "No. of unique datagrams received:", self.unique
                                                   print "No. of bytes received:",self.receivedbytescount
						   throughput = self.receivedbytescount/self.total
						   print "Throughput:",throughput, "bytes per second"
                                                   #print "Goodput:", self.goodput
                                                   endproc = 1
                                                   print >>sys.stderr, 'closing socket'

                                                   self.receive = 0
                                                   break
                                                   return
                                   else:
                                           print" Unexpected sequence number. Expected seq no:", self.seq_expected ,"Actual received:",self.server_seq
                                           self.datagram = struct.pack('3i s',self.seq,self.ack,self.flag,self.new)
                                           self.sent = self.sock.sendto(self.datagram, self.server_address)
                except KeyboardInterrupt:
                    print 'errorists win2'
                    sys.exit(2)
                #except Exception, e:
                #    print type(e)  # Should give you the exception type
                return

        def write_file(self):
                while True:
                    try:# while endproc(receive is not done yet no fin bit and data to be written exists keep popping deque)
                        if (self.dataremaining > 0) & (endproc ==0):
                                self.fo.write(rcvbuf.popleft())
                                self.dataremaining = self.dataremaining-1
                        elif (self.dataremaining > 0) & (endproc ==1):
                                self.fo.write(rcvbuf.popleft())
                                self.dataremaining = self.dataremaining-1
                        elif (endproc ==1)& (self.dataremaining == 0):
                                self.fo.write(rcvbuf.popleft())
                        else:
                                self.cyclelost +=1 #count loop doing nothing

                        #print len(rcvbuf)
                    except IndexError:
                        self.fo.close()
			print ("File received successfully. Program will now exit.")
                        break
try:

        client_f = client()
        print "FILE RECEIVE MODE"
        left = threading.Thread(target=client_f.receive_file)
        consume = threading.Thread(target = client_f.write_file)

        left.start()
        time.sleep(0.3)
        consume.start()

        left.join()
        consume.join()

        sys.exit()
except KeyboardInterrupt:
	sys.exit(2)

#if __name__ == "__main__":
#	if len(sys.argv) < 15:
#		print 'Not enough arguments. Input with -h for help.'
