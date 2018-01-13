# Linux Packet Sniffer
A simple linux packet sniffer written in python using primarily the sockets API.

Features:
* Listens to incoming IP packets for a specified duration
* A port whitelist and IP whitelist can be set to filter out only packets of interest
* If no whitelists are provided, all incoming IP packets are recorded and analyzed
* The verbose option prints out packet information in real time to the console
* At the end of the recording session, statistics are provided
* TCP and UDP tests are also included in test_module. A localhost server is set up on a separate thread and a packet is sent through a localhost client socket to the localhost server. The packet sniffer is tested to see if it catches the packet.

# Screenshots
![Real time verbose output](https://github.com/yarnspinnered/py_packet_sniffer/blob/master/img/Summary.png?raw=true "Real-time output")
![Summary statistics](https://github.com/yarnspinnered/py_packet_sniffer/blob/master/img/Verbose.png?raw=true "End statistics")