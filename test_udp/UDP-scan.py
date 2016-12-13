import socket
host = "scanme.nmap.org"            


port_list = [53,61]
for port in port_list:
	try:
		s = socket.socket(AF_INET, SOCK_DGRAM)
		s.settimeout(0.1)
		data = "Hello"
		#print "Try "+str(port)
		s.sendto(data,(host,port))
		recv, svr = s.recvfrom(255)
		print ('{} {}'.format(recv,svr))
		s.close()
	except Exception, e:
		print ('{}/udp \tclosed'.format(port))
