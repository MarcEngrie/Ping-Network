# Ping-Network

This is a Python script (also converted to an Windows executable) that allows you to scan your network(s) and find availablr devices.
Initially, you can run it like this eg:
~~~
python.exe Ping-Network.py -N "192.168.1" -M "255.255.255.0"

or

Ping-Network.exe -N "192.168.1" -M "255.255.255.0"
~~~

This will scan the whole network 192.168.1.0/24 from 192.168.1.1 to 192.168.1.254. All devices that reply to a ping will be listed in a file called PingNetwork_192.168.1.txt.
If they have a DNS-record in the DNS server used, a hostname will be added.
A second file PingNetwork_192.168.1.lan is created listing all alive IP's with their hostname, if available, and their MAC-address.
In the file you find a seoncd list with all IP's (alive and not responding). So you can see what IPs are still available.  

You can edit the file to add or correct what is needed. Then, rename it to PingNetwork_192.168.1.lst.
When you run the tool like this
~~~
python.exe Ping-Network.py -P "PingNetwork_192.168.1.lst" -N "192.168.1" -M "255.255.255.0"

or

Ping-Network.exe -P "PingNetwork_192.168.1.lst" -N "192.168.1" -M "255.255.255.0"
~~~

the tool will do a full scan of the network as well as a specific scan of all devices list in PingNetwork_192.168.1.lst. 
Any deivce not responding will be reported. Any device alive and not in the list will also be reported. 

Reporting can be controlled in the corresponding YAML file
~~~
PRINT:
    Enabled: True

FILE:
    Enabled: True

SMTP:
  Enabled: True
  # # smtp info
  Server: smtp.home
  Port: 587
  TLS: True
  CA: False
  Login: ""
  Password: ""
  MailDomain: engrie.home  
  To: marc@engrie.home
~~~

Sample of .lst file
~~~
# Format: hostname;IP-address;Status 
# Status can be A = Active or O = occasionally
################################################
### Internal netwerk - 192.168.1
################################################
#-----------------------------------------------
# Fixed IP
#-----------------------------------------------
router;192.168.1.1;A
ap-tpwr802n-Engrie4;192.168.1.2;A
ap-tpwr802n-Comicsken;192.168.1.3;A
ap-tplinkeap615L;192.168.1.4;A
pl-tplinkwpa7510G;192.168.1.5;A
ap-tplinkeap225B;192.168.1.6;A
ap-tplinkeap115B;192.168.1.7;A
ap-tplinkeap615G;192.168.1.8;A
devolo-5400;192.168.1.9;A
sw-netgeargs116eB;192.168.1.10;A
sw-netgeargs308eppB;192.168.1.11;A
sw-netgeargs308eppG;192.168.1.12;A
sw-netgeargs305eppK;192.168.1.13;A
storage1;192.168.1.16;A
storage2;192.168.1.17;A
octopi;192.168.1.66;O
#-----------------------------------------------
# DHCP reservations
#-----------------------------------------------
chromecast-bedroom;192.168.1.61;A
daikin-bedroom;192.168.1.103;A
daikin-bureau;192.168.1.107;A
daikin-keuken;192.168.1.47;A
daikin-living;192.168.1.68;A
dell5580-marleen;192.168.1.53;A
~~~

Sample of .lan file

