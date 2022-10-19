Verdale Betts
CIS 457 Project 2: Virtual Router

----- run in terminal ------
xhost +local:
sudo python3 prj2-net.py

---- run un mininet --------
xterm r1 r2 h1 h2 h3 h4 h5

---------------------------- TO DO: PART ONE ------------------------------ 
------ TODO: -----------
  - Router accepts packets on packet sockets
  - Builds correct ARP response (including ethernet header)
  - Builds correct ICMP echo reply (including ethernet and ip headers)
  - Correctly uses packet socket to send responses as appropriate
  - All of the above work on all router interfaces 
------------------------

  For part one, your router must correctly deal with arp requests and ICMP echo requests. When your router gets an ARP request for one of its IP addresses, it must send out an ARP response on the same socket, back to the sender of the ARP request. The MAC address indicated in the ARP reply should be one for the same interface as the IP address indicated in the request. ARP packets consist of an Ethernet header and an ARP header. No IP header is used. 
  
  Additionally for part one, your router must correctly respond to ICMP echo request packets with any of its own IP addresses as the destination. The correct action to take when receiving an ICMP echo request is to send an ICMP echo reply with the same ID, sequence number, and data as the response. You must correctly construct the Ethernet, IP, and ICMP headers.
  
  Once these two steps are completed, a host should be able to successfully ping the router interface it is connected to. If ARP is working but not ICMP, ping on the host should be sending ICMP echo request, and they should be seen on the router. If ARP is not working, the ICMP echo requests will not be sent. If your ARP implementation is not yet correctly working, you may test ICMP by re-enabling the operating system's ARP responses which we have disabled for this project.
