# Espionage - A Network Traffic Interceptor For Linux
<p align="center">
  <img src="https://github.com/josh0xA/Espionage/blob/master/imgs/espionage_logo.png?raw=true">
</p>

<p align="center">
  <br>
  <b>Featured In</b>
  <br>
  <a href="https://blackarch.org/sniffer.html"><img src="https://i.imgur.com/IPiAUZi.png">
  <a href="https://www.kitploit.com/2020/06/espionage-network-packet-and-traffic.html"><img src="https://raw.githubusercontent.com/josh0xA/Espionage/master/imgs/kitploit-Logo-2015-04-27%252B-%252B%2525283%252529.png"></a>
</p>
  
<p align="center">
    <a href="https://lbesson.mit-license.org/" target="_blank"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="lisence" /></a>
    <a href="https://www.python.org/" target="_blank"><img src="https://img.shields.io/badge/Made%20with-Python-1f425f.svg"/></a>
</p>

## About Espionage
Espionage is a network packet sniffer that intercepts large amounts of data being passed through an interface. The tool allows users to to run normal and verbose traffic analysis that shows a live feed of traffic, revealing packet direction, protocols, flags, etc. Espionage can also spoof ARP so, all data sent by the target gets redirected through the attacker (MiTM). Espionage supports IPv4, TCP/UDP, ICMP, and HTTP. Espionage was written in Python 3.8 but it also supports version 3.6. This is the first version of the tool so please contact the developer if you want to help contribute and add more to Espionage. Note: This is not a Scapy wrapper, scapylib only assists with HTTP requests and ARP. 

## Installation
1: ```git clone https://www.github.com/josh0xA/Espionage.git```<br/>
2: ```cd Espionage```<br/>
3: ```sudo python3 -m pip install -r requirments.txt```<br/>
4: ```sudo python3 espionage.py --help```<br/>

## Usage
1. ```sudo python3 espionage.py --normal --iface wlan0 -f capture_output.pcap```<br/>
Command 1 will execute a clean packet sniff and save the output to the pcap file provided. Replace ``wlan0`` with whatever your network interface is.<br/>
2. ```sudo python3 espionage.py --verbose --iface wlan0 -f capture_output.pcap```<br/>
Command 2 will execute a more detailed (verbose) packet sniff and save the output to the pcap file provided.<br/>
3. ```sudo python3 espionage.py --normal --iface wlan0```<br/>
Command 3 will still execute a clean packet sniff however, it will not save the data to a pcap file. Saving the sniff is recommended. <br/>
4. ```sudo python3 espionage.py --verbose --httpraw --iface wlan0```<br/>
Command 4 will execute a verbose packet sniff and will also show raw http/tcp packet data in bytes. <br/>
5. ```sudo python3 espionage.py --target <target-ip-address> --iface wlan0```<br/>
Command 5 will ARP spoof the target ip address and all data being sent will be routed back to the attackers machine (you/localhost). <br/>
6. ```sudo python3 espionage.py --iface wlan0 --onlyhttp```<br/>
Command 6 will only display sniffed packets on port 80 utilizing the HTTP protocol.<br/>
7. ```sudo python3 espionage.py --iface wlan0 --onlyhttpsecure```<br/>
Command 7 will only display sniffed packets on port 443 utilizing the HTTPS (secured) protocol.<br/>
8. ```sudo python3 espionage.py --iface wlan0 --urlonly```<br/>
Command 8 will only sniff and return sniffed urls visited by the victum. (works best with sslstrip).<br/><br/>
* Press Ctrl+C in-order to stop the packet interception and write the output to file. <br/>

## Menu
```
usage: espionage.py [-h] [--version] [-n] [-v] [-url] [-o] [-ohs] [-hr] [-f FILENAME] -i IFACE
                    [-t TARGET]

optional arguments:
  -h, --help            show this help message and exit
  --version             returns the packet sniffers version.
  -n, --normal          executes a cleaner interception, less sophisticated.
  -v, --verbose         (recommended) executes a more in-depth packet interception/sniff.
  -url, --urlonly       only sniffs visited urls using http/https.
  -o, --onlyhttp        sniffs only tcp/http data, returns urls visited.
  -ohs, --onlyhttpsecure
                        sniffs only https data, (port 443).
  -hr, --httpraw        displays raw packet data (byte order) recieved or sent on port 80.

(Recommended) arguments for data output (.pcap):
  -f FILENAME, --filename FILENAME
                        name of file to store the output (make extension '.pcap').

(Required) arguments required for execution:
  -i IFACE, --iface IFACE
                        specify network interface (ie. wlan0, eth0, wlan1, etc.)

(ARP Spoofing) required arguments in-order to use the ARP Spoofing utility:
  -t TARGET, --target TARGET
```
[![asciicast](https://asciinema.org/a/343152.svg)](https://asciinema.org/a/343152)
## Discord Server
https://discord.gg/jtZeWek

## Ethical Notice
The developer of this program, Josh Schiavone, written the following code for educational and ethical purposes only. The data sniffed/intercepted is not to be used for malicous intent. Josh Schiavone is not responsible or liable for misuse of this penetration testing tool. May God bless you all.

### License
MIT License<br/>
Copyright (c) 2020 Josh Schiavone

<br/>


