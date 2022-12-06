# writeup
IDS Project

# Attack
This attack scenario is atargeted compromise of an enterprise enviornment such as the worm with logic bomb payload that struck the Saudi Aramco company. The attack sequence as a general overview is as follows: An attacker compromises a host on the network via a poisoned dpkg package. This will install the bot agent on the compromised host and will immediatley attempt to start traversing the network. Meanwhile, one of the hosts on the network segment must have the c2 server installed. This could be an attacker machine on the network or a compromised machine communicating with a remote attacker through a reverse shell.

## Covert Channel
The covert channel used by the botnet was custom written for this project and implimented as a python library built on top of the scapy packet manipulation tool. Both the bot and C2 server impliment this library for their communications. 

### Data payload
The communications for the botnet's C2 is a custom protocol dubbed AuRevior (get it, like Apple Bonjour). It is built on mDNS on UDP on IP. mDNS (Multicast DNS) is a common protocol for local network service discovery, implimented by daemons like `avahi` for linux. It is very common for hosts to be sending large amounts of multicast traffic of this procol on an enterprise network to discover services such as printers. AuRevior works by encoding bits as mDNS packets from different source ports. These are sent is bursts or windows of 0.25 seconds and each window encodes 1 byte of payload data for a fixed transmission rate of 4 bytes per second. Each bit is encoded by wheather or not an mDNS packet was sent from the corresponding source port during the window. By default the mDNS packet source ports range from 5350 to 5357. These packets all have a qclass of 255 (any).

For example, if a user wanted to transmit the data `0xAA` (0b10101010) the user would send 4 mDNS packets within 0.25 seconds. The packets would originate from ports 5350, 5352, 5354, and 5356 respectivley. Conversley, if the user wanted to send `0x1` (0b00000001), they would send 1 mDNS packet in the 0.25 second frame, with a source port of 5357.

The payload of each mDNS packet is a standard mDNS query and does not encode any information*. Should an IDS inspect each individual packet, it would not find anything out of the ordinary. The information is encoded soleley by which packets were sent when. The payload has a variable length and the sender will transmit 1 byte every quarter second until it is finished. 

The transmit windows are so big and thus the data rate is so slow because we want to minimize the impact of network latency changes and because we don't want the IDS to think we're trying to flood the network by transmitting massive amounts of mDNS traffic at once.

### Preamble
Each transmission is proceded by a 4 byte preamble of vaues 0x55, 0xAA, 0x55, 0xAA. (every odd bit, every even bit, repeat). This serves three important purposes:
1- Indicates that a transmission is starting
2- Serves as a synchronization source as the 0.25 second windows are timed starting at the end of the preamble transmission
3- encodes the checksum for the following payload.

The first two are rather self explanatory, however the checksum encoding is more intersting. Remember how we said that nothing was encoded in the mDNS packets themselves? That was a lie. This is true for the data packets but not for the preamble packets. One of the fields of an mDNS packet is the `qclass` or query class field. In normal communications, this is almost always set to 1 for "Internet", however the RFC has 5 valid (although mostly depricated) values for this field. The protocol takes the first 4 of these symbols and uses them to encode the binary values 00, 01, 10, and 11 respectivley. This gets us 2 bits per packet and the preamble has 4 packets per frame. 2 bits/packet * 4 packets/frame * 4 frames/preamble = 32 bits of data which can be encoded in the preamble. For data integrity, AuRevior uses this to transmit a 16 bit checksum twice.

### Post-amble
While postamble may not be a word, it is a part of the AuRevior transmission. This is 1 window of data with a value of `0xFF` and qclass of 1. This simply notifies the reciever that the transmission is finished and does not contain any further data. 


## The bot
The bot is an agent written in python, registered as a systemd service. It has the following features: Domain traversal via ssh, keylogger (simulated), and command and control communications over convert channels.

### Installation
The bot is installed as part of a tampered VScode dpkg package. the reason we chose this is that VScode is popular software which is not in ububtu's default repositories which means this is one of the few programs for Linux that is expected to be installed by root from a package downloaded from a website. This allows us to bypass linux's package management security model. 
As part of the installation, the bot installs itself to `/usr/bin/avahi-ng` and registers an auto-enabled systemd service by the same name. Avahi is the most common mDNS / Bonjour/ Zeroconf utility for linux so an application called avahi-ng broadcasting mDNS packets will not raise suspision. The installer will also mask the real avahi service to prevent it from interfering. 

### Traversal
The bot, while listening for c2 messages, also keeps a list of every IP it has seen traffic of any type from. When traversing, it will attempt to connect to IPs in this list first and then will start iterating through its local network segment. As the target is an orgainzation, it almost certainly uses a centralized login system such as Active Directory or LDAP. As such, credentials that worked on the bot's machine should work on most other machines. In the real world the bot would steal these credentials with a keylogger, but this is a malicious payload and not permitted. As such, the bot will have a set of credentials hard-coded. Let it be known that on machines such as the CS2011 VMs, using X11 and not using SElinux, creating a keylogger for this bot would be trivial so the stand-in credientials is reasonable. 

With these credentials and ip sets, the bot will first attempt an ICMP ping to see if an IP is up and, if it is, ssh in with its credentials. Again, tools like SSH, RDP, and VNC, are common on enterprise networks and should not raise too much suspicion, especially since the credentials are already known and not brute-forced. Having establised an SSH connection, the bot will install itself on the new host and then close the connection.

### Command and Control
The bots use the C2 mDNS covert channel described in the "covert channel" section above. the bot constantly listens for mDNS traffic and will attempt to parse it. If the message is a command and is destined for the bot's ID, it will execute it and transmit a reply. 
