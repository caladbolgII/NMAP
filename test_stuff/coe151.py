import random, socket, sys, time, hashlib
import logging
import threading
import time
from random import choice
from string import lowercase
from decimal import Decimal
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


logging.basicConfig(level=logging.CRITICAL,
					format='%(asctime)s (%(threadName)-2s) %(message)s')

MAX = 65535
PORT = 1085
PORT_TCP = 1092
WINDOW_SIZE = 5
PACKET_SIZE = 928

RETURNED_PACKETS = 0
PACKET_LOSS = 0
DELAY = 0.001

temp_packet = "0"*PACKET_SIZE
a_packet = 'a'*PACKET_SIZE


packet_percentage_list = []
throughput_list = []
rtt_list = []




if 2<= len(sys.argv) <= 3 and sys.argv[1] == 'receiver':
	interface = sys.argv[2] if len(sys.argv) > 2 else ''
	s.bind((interface, PORT))
	s.settimeout(DELAY)
	logging.debug('Listening at %s', s.getsockname() )

	s_tcp.bind((interface, PORT_TCP))
	s_tcp.settimeout(30)
	s_tcp.listen(1)
	try:
		conn, addr = s_tcp.accept()
	except (KeyboardInterrupt, SystemExit):
		conn.close()
		s.close()
	except:
		raise
	interval = 0

	received_packets = 0
	counter_elapsed = 0
	delta = 0
	throughput = 0
	unpacked_data0 = 0
	unpacked_data1 = 0

	decrease_time = 0


	while True:

		while True:
			try:
				tcp_data = conn.recv(8)
				unpacked_data0, unpacked_data1 = struct.unpack('2i', tcp_data)
				interval = unpacked_data0
				break
			except socket.timeout:
				logging.debug("Socket timeout finding throughput")
				#print "Socket timeout finding throughput"
			except (KeyboardInterrupt, SystemExit):
				conn.close()
				s.close()
			
		# Receive packets 0.97 of time interval
		throughput_interval = 0.97*interval

		received_packets = 0
		delta = 0
		time_start = time.time()
		received_data = 0

		decrease_time = 0
		while (delta <= throughput_interval):
			decrease_time_start = time.time()
			try:
				data, address = s.recvfrom(MAX)	
				received_packets = received_packets + 1
				received_data = received_data + sys.getsizeof(data)
			except socket.timeout:
				#print "Socket timeout throughput"
				decrease_time = decrease_time + (time.time() - decrease_time_start)
				#decrease_time = decrease_time + 1
			except (KeyboardInterrupt, SystemExit):
				conn.close()
				s.close()
			except:
				raise

				
			delta = time.time() - time_start

		# Send signal done receiving
		done_packet = struct.pack('2i', 1, 1)
		conn.sendall(done_packet)
		
		# Get # of expected packets
		while True:
			try:
				tcp_data = conn.recv(8)
				unpacked_data0, unpacked_data1 = struct.unpack('2i', tcp_data)
				expected_packets = unpacked_data0
				break
			except socket.timeout:
				logging.debug("Socket timeout get expected packets")
				#print "Socket timeout get expected packets"
			except (KeyboardInterrupt, SystemExit):
				conn.close()
				s.close()

		# Send a packet for RTT
		s.settimeout(DELAY*4)
		
		#time.sleep(5)
		rtt = 0
		break_packet = 0
		lost_packet = 0
		rtt_start = time.time()
		s.sendto(a_packet,address)	
		has_rtt = 0

		while True:
			try:
				data, address = s.recvfrom(MAX)	
				#print "RTT_PACKET: ", str(data)
				if (data == a_packet):
					rtt = time.time() - rtt_start
					#print "RTT: ", str(rtt)
					has_rtt = 1;
					break
				
			except socket.timeout:
				logging.debug("Socket timeout RTT")
				#print "Socket timeout RTT"
		
				
			except (KeyboardInterrupt, SystemExit):
				conn.close()
				s.close()
			except:
				raise	

		

		elapsed_time = delta - (decrease_time)
		packet_percentage = (float(expected_packets-received_packets)/expected_packets)*100
		throughput = float(received_data*8)/elapsed_time
		
		throughput_list.append(float(throughput)/(1000*1000))
		packet_percentage_list.append(packet_percentage)

		if (has_rtt == 1):
			
			rtt_list.append(rtt)
			print "RTT: ", str(rtt)
		else:
			print "RTT: Lost packet for RTT"
		print "Elapsed Time: ", str(elapsed_time)
		print "Expected packets: ", str(expected_packets)
		print "Received packets: ", str(received_packets)		
		print "Packet Loss %: ", str(packet_percentage)		
		print "Throughput(bits): ", str(throughput)
		print "Throughput(Mbits): ", str(float(throughput)/(1000*1000))
		print " "
		print "RTT: ", str(max(rtt_list))," (max), ", str(min(rtt_list))," (min), ", str(sum(rtt_list)/len(rtt_list))," (ave) "
		print "Packet Loss: ", str(max(packet_percentage_list))," (max), ", str(min(packet_percentage_list))," (min), ", str(sum(packet_percentage_list)/len(packet_percentage_list))," (ave) "
		print "Throughput (Mbits): ", str(max(throughput_list))," (max), ", str(min(throughput_list))," (min), ", str(sum(throughput_list)/len(throughput_list))," (ave) "
		print " "

		

elif len(sys.argv) == 3 and sys.argv[1] == 'sender':
	hostname = sys.argv[2]
	s.connect((hostname,PORT))
	print "Connected"
	s_tcp.connect((hostname,PORT_TCP))
	delta = 0
	interval = int(raw_input("Enter time interval: "))

	while True:
		# Send packet containing time interval
		start_packet= struct.pack('2i', interval, interval)
		s_tcp.send(start_packet)

		# Send packets 0.95 of time interval
		throughput_interval = 0.92*interval
		delta = 0
		sent_packets = 0

		# Leeway time for receiver
		time.sleep(0.02*interval)

		# Start sending packets
		time_start = time.time()
		while (delta <= throughput_interval):
			s.send(temp_packet)
			sent_packets = sent_packets + 1
			delta = time.time() - time_start


		# Receive confirmation that server stopped receiving
		while True:
			try:
				start_msg = s_tcp.recv(8)
				unpacked_data0, unpacked_data1 = struct.unpack('2i', start_msg)
				if (unpacked_data0 == 1):
					break
				else:
					logging.debug("Error with stage 2 confirm")
					#print "Error with stage 2 confirm"
					exit()
			except (KeyboardInterrupt, SystemExit):
				conn.close()
				s.close()
			except: 
				raise


		print "Sent packets: ", str(sent_packets)
		#print "Throughput Interval(0.95): ", str(throughput_interval)

		# Send # of sent packets to server
		expected_packet= struct.pack('2i', sent_packets, sent_packets)
		#print "Expected Packets: ", str(expected_packet[0])
		s_tcp.send(expected_packet)
		
		#time.sleep(5)
		# Receive and send back packet for RTT
		break_packet = 0
		lost_packet = 0
		while True:
			try:
				rtt_packet = s.recv(MAX)
				#print "RTT PACKET: ", str(rtt_packet)
				if (rtt_packet == a_packet):
					s.send(rtt_packet)
					break
			except socket.timeout:
					logging.debug("Socket timeout rtt")
					#print "Socket timeout rtt"
				
			except (KeyboardInterrupt, SystemExit):
					conn.close()
					s.close()
			except: 
				raise
			

	

		time.sleep(0.005)

