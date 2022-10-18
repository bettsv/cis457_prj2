CIS 457 Project 2: Virtual Router


Program Overview:
  You must write the (simplified) functionality of the routers in software. Each of the routers must run the same program (although different configuration files, user input, or command line parameters may be specified). The routers are simplified in the sense that they use a small statically defined routing table; they do not participate in any actual routing protocols.
Specifically, by the time you are done, the following functionality must work

• The router must respond to a ping to any of its interfaces.
• The router must be visible in traceroutes between end hosts attached to different ports
• The router must correctly route all IPv4 traffic to end hosts.
• When the router recieves a packet it can not route, it must send the appropriate ICMP
message back to the sender.

  Router one should use the routing table r1-table.txt, and router two should use the routing table r2-table.txt, both available on blackboard. The table has three columns: a network prefix, an IP address of a next hop device if applicable, and an interface. Packets matching the prefix on a line in this table should be forwarded on the indicated interface. The next hop IP address indicates which device the packet should be forwarded to. If there is no next hop IP address for a prefix, the packet should be forwarded to the destination IP address specified in the packet's IP header.

  Your program may be written in C, C++, Python. It is highly recommended that you complete
this project in C++. This program requires the use of packet sockets. These are sockets that
provide access to the entire packet (all headers). Starter code is provided only in C (and should
compile fine as C++). If using python, it is up to you to translate the starter code. The netifaces
library will be needed to get a list of network interfaces. Java does not provide any access to
packet sockets. Therefore, this project can not be completed in Java. You must open one socket
per interface on the router, and be able to process packets arriving on any of these interfaces.


----- run in terminal ------
xhost +local:
sudo python3 prj2-net.py

---- run un mininet --------
xterm r1 r2 h1 h2 h3 h4 h5

---------------------------- PART ONE ------------------------------

  For part one, your router must correctly deal with arp requests and ICMP echo requests. When your router gets an ARP request for one of its IP addresses, it must send out an ARP response on the same socket, back to the sender of the ARP request. The MAC address indicated in the ARP reply should be one for the same interface as the IP address indicated in the request. ARP packets consist of an Ethernet header and an ARP header. No IP header is used. 

  Additionally for part one, your router must correctly respond to ICMP echo request packets with any of its own IP addresses as the destination. The correct action to take when receiving an ICMP echo request is to send an ICMP echo reply with the same ID, sequence number, and data as the response. You must correctly construct the Ethernet, IP, and ICMP headers.
Once these two steps are completed, a host should be able to successfully ping the router interface it is connected to. If ARP is working but not ICMP, ping on the host should be sending ICMP echo request, and they should be seen on the router. If ARP is not working, the ICMP echo requests will not be sent. If your ARP implementation is not yet correctly working, you may test ICMP by re-enabling the operating system's ARP responses which we have disabled for this project.
