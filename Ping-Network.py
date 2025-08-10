###################################################################################
#
# some stuff I need sometimes
#
#  pyinstaller --onefile "Ping-Network.py" --exclude-module pkg_resources
#
###################################################################################

###################################################################################
### Imports, defines, variables, objects, ...
###################################################################################
import sys, getopt
import os
import smtplib, ssl
import socket
import struct
import time
import select
import netifaces
import socket
import subprocess
import re
import ipaddress
import yaml

from requests             import get
from datetime             import datetime        as dt
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from scapy.all            import srp, Ether, ARP

#----------------------------------------------------------------------------------

VERSION        = "3.00"
Debug          = False

COMPUTERNAME   = os.getenv('COMPUTERNAME')

strScriptName  = os.path.basename(sys.argv[0])
strScriptBase  = os.path.splitext(strScriptName)[0]
yamlFilename   = strScriptBase + '.yaml'

#----------------------------------------------------------------------------------

# Ping related
Count          = "3"
Size           = "256"
PingList       = ""
PingDict       = {}
Timeout        = 300

print_enabled  = False
file_enabled   = False
file_name      = ""

# SMTP related
smtp_enabled   = False
smtpserver     = "smtp.home"
smtpport       = 587
smtptls        = True
smtpCA         = False
smtplogin      = ""
smtppass       = ""
From           = ""
To             = ""

# IP related
IP_NET         = ""
IP_MASK        = ""
host_ip        = ""
host_mac       = ""
host_net       = False
ipalive        = []
ipnet          = []
ipa            = []
ipu            = []
arpalive       = []

# Output file
outputFile     = ""

#----------------------------------------------------------------------------------
# setup ssl
# Create a secure SSL context
sslcontext = ssl.create_default_context()
if smtptls:
    try:
        ssl._create_unverified_https_context = ssl._create_unverified_context

    except AttributeError:
        # Legacy Python that doesn't verify HTTPS certificates by default
        pass

###################################################################################
### Classes
###################################################################################
#----------------------------------------------------------------------------------
ICMP_ECHO_REQUEST =   8 # Platform specific
DEFAULT_COUNT     =   5 # number of pings to send
DEFAULT_SIZE      =  64 # ping packet size
DEFAULT_TIMEOUT   = 300 #in milliseconds

class Pinger(object):
    """ Pings to a host -- the Pythonic way"""

    def __init__(self, target_host, count=DEFAULT_COUNT, size=DEFAULT_SIZE, timeout=DEFAULT_TIMEOUT, debug=False):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout / 1000  # convert to seconds - select uses seconds
        self.size = size
        self.debug = debug

    def do_checksum(self, source_string):
        """  Verify the packet integritity """
        sum = 0
        max_count = (len(source_string)/2)*2
        count = 0
        while count < max_count:
            val = source_string[count + 1]*256 + source_string[count]
            sum = sum + val
            sum = sum & 0xffffffff
            count = count + 2

        if max_count<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff

        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def receive_pong(self, sock, ID, timeout):
        """
        Receive ping from the socket.
        """
        time_remaining = timeout
        while True:
            start_time = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = (time.time() - start_time)
            if readable[0] == []: # Timeout
                return

            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            icmp_header = recv_packet[20:28]
            type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmp_header)
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent

            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return

    def send_ping(self, sock,  ID):
        """
        Send ping to the target host
        """
        target_addr  =  socket.gethostbyname(self.target_host)

        my_checksum = 0

        # Create a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_In_double = struct.calcsize("d")
        data = (192 - bytes_In_double) * "Q"
        data = struct.pack("d", time.time()) + bytes(data.encode('utf-8'))

        # Get the checksum on the data and the dummy header.
        my_checksum = self.do_checksum(header + data)
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1)
        packet = header + data
        sock.sendto(packet, (target_addr, 1))

    def ping_once(self):
        """
        Returns the delay (in seconds) or none on timeout.
        """
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error as e:
            if e.errno == 1:
                # Not superuser, so operation not permitted
                e.msg +=  "ICMP messages can only be sent from root user processes"
                raise socket.error(e.msg)
        except Exception as e:
            if self.debug:
                print("Exception: %s" %(e))

        my_ID = os.getpid() & 0xFFFF

        self.send_ping(sock, my_ID)
        delay = self.receive_pong(sock, my_ID, self.timeout)
        sock.close()
        return delay

    def ping(self):
        """
        Run the ping process
        """

        max=0
        min=0
        los=0
        tot=0

        for i in range(self.count):
            try:
                delay  =  self.ping_once()
            except socket.gaierror as e:
                if self.debug:
                    print("Ping failed. (socket error: '%s')" % e[1])
                    break

            if delay  ==  None:
                # print("Ping failed. (timeout within %ssec.)" % self.timeout)
                if self.debug:
                    print("Request timed out.")
                delay = int(self.timeout * 1000)
                los = los+1

            else:
                delay  =  int(delay * 1000)
                if self.debug:
                    print("Reply from %s" % self.target_host,end = '')
                    print(" time=%0.0fms" % delay)

            if delay > max:
                max=delay
            if delay < min:
                min=delay
            tot = tot + delay

        los = int((los/self.count)*100)
        return max, min, int(tot/self.count), los

#----------------------------------------------------------------------------------

###################################################################################
### Functions
###################################################################################

#----------------------------------------------------------------------------------
def getargs(argv):

    global strScriptName
    global Count, Size, Timeout
    global MailHost, MailTo, MailFrom
    global PingList, IP_NET, IP_MASK
    global outputFile

    try:
        opts, args = getopt.getopt(argv,"Dc:l:t:h:t:f:P:N:M:")
    except getopt.GetoptError:
        print(strScriptName + ".py host [-D] [-c count] [-l length] [-t timeout] [ -h MailHost ] [ -t to ] [ -f from ] [ -P filename ] -N net_to_scan [-M mask ]")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-D':
            Debug = True
        elif opt in ("-c"):
            Count = arg
            if not Count.IsNumeric():
                print("FATAL: option -c requires numeric argument.", file=sys.stderr)
                sys.exit(255)
        elif opt in ("-l"):
            Size = arg
            if not Count.IsNumeric():
                print("FATAL: option -l requires numeric argument.", file=sys.stderr)
                sys.exit(255)
        elif opt in ("-t"):
            Timeout = arg
            if not Count.IsNumeric():
                print("FATAL: option -t requires numeric argument.", file=sys.stderr)
                sys.exit(255)
        elif opt in ("-h"):
            MailHost = arg
        elif opt in ("-t"):
            MailTo = arg
        elif opt in ("-f"):
            MailFrom = arg
        elif opt in ("-P"):
            PingList = arg
            loadPingDict()
        elif opt in ("-N"):
            IP_NET = arg
            outputFile = strScriptBase + f"_{IP_NET}.lan"
        elif opt in ("-M"):
            IP_MASK = arg

    if IP_NET == "":
        print("Error: -N <net_to_scan>  is a mandatory option.")
        print("Eg: -N 192.168.1")
        sys.exit(2)

    if IP_MASK == "":
        IP_MASK = "255.255.255.0"
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def loadPingDict():

    global PingList, PingDict

    with open(PingList, "r") as fh:
        for line in fh:
            line = line.strip()
            if len(line) > 0:
                if line[0] != '#':
                    if line.find(";") != -1:
                        ip_split = line.split(";")
                        hostname = ip_split[0].strip()
                        ip       = ip_split[1].strip()
                        act      = ip_split[2].strip()

                        # Format last part with 3 digits, padded with zeros
                        ip_split = ip.split(".")
                        ip_split[0] = f"{int(ip_split[0]):3d}"
                        ip_split[1] = f"{int(ip_split[1]):03d}"
                        ip_split[2] = f"{int(ip_split[2]):03d}"
                        ip_split[3] = f"{int(ip_split[3]):03d}"
                        ip_15 = ".".join(ip_split)
                        PingDict[ip_15] = hostname
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
# general routine to send mails
def sendmail(From, To, Subject, Body, Attach = ""):

    global smtpserver, smtpport, smtptls, smtpCA, smtplogin, smtppass, sslcontext

    msg            = MIMEMultipart()
    msg['From']    = From
    msg['To']      = To
    msg['Subject'] = Subject

    msg.attach(MIMEText(Body, 'plain'))

    if Attach != "":
        attachment = open(Attach, "rb")
        part = MIMEBase('application', 'octet-stream')
        part.set_payload((attachment).read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', "attachment; filename= %s" % Attach)
        msg.attach(part)

    dteNow       = dt.now()
    timestamp    = dteNow.strftime("%Y-%m-%d %H:%M:%S")
    strMessage   = timestamp + " - Sending email from " + From + " to " + To + " with subject : " + Subject
    if Debug:
        print(strMessage)

    server = smtplib.SMTP(smtpserver, smtpport)
    try:

        #server.ehlo()                  # Can be omitted
        if smtptls and not smtpCA:
            server.starttls()           # Secure the connection
        elif smtptls and smtpCA:
            server.starttls(sslcontext) # Secure the connection
        #server.ehlo()                  # Can be omitted
        if smtplogin != "":
            server.login(smtplogin, smtppass)
        text = msg.as_string()
        server.sendmail(From, To, text)
        dteNow       = dt.now()
        timestamp    = dteNow.strftime("%Y-%m-%d %H:%M:%S")
        strMessage   = timestamp + " - Sent    email from " + From + " to " + To + " with subject : " + Subject

    except Exception as e:
        dteNow       = dt.now()
        timestamp    = dteNow.strftime("%Y-%m-%d %H:%M:%S")
        strMessage   = ""
        strMessage   = strMessage + timestamp + " - Failed to sent email from " + From + " to " + To + " with subject : " + Subject + "\n"
        strMessage   = strMessage + timestamp + " -    Error : " + e

    finally:
        server.quit()

    if Debug:
        print(strMessage)
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def extend_ip(partial_ip, netmask):
    # Split and pad the IP to 4 octets
    octets = partial_ip.split('.')
    while len(octets) < 3:
        octets.append('0')  # You can use '1' or another default if preferred
    octets.append('1')
    full_ip = '.'.join(octets)

    # Create the network
    network = ipaddress.IPv4Network(f"{full_ip}/{netmask}", strict=False)
    return network
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def doping(Host, Count, Size, Timeout, Debug):

    global ipalive, IP_NET, host_net

    min      = Timeout
    max      = Timeout
    avg      = Timeout
    los      = 100
    host     = ""
    ip       = ""
    acti     = ""
    DNS_host = ""
    DNS_ip   = ""

    if Host.find(";") != -1:
        ip_split = Host.split(";")
        host = ip_split[0].strip()
        ip   = ip_split[1].strip()
        act  = ip_split[2].strip()
        ip_split.remove(host)
        host = host.replace(".home","")
        host = host.replace(".local","")
        if IP_NET in ip:
            try:
                DNS_ip = socket.gethostbyname(host)
            except:
                DNS_ip = ""

            try:
                DNS_host, _, _ = socket.gethostbyaddr(ip)
                DNS_host = DNS_host.replace(".home","")
            except:
                DNS_host = ""
    else:
        host = Host.replace(".home","")
        try:
            DNS_ip = socket.gethostbyname(host)
        except:
            DNS_ip = ""

    if Debug:
        print(Host, host, DNS_host, ip, DNS_ip)

    if IP_NET in ip and host_net:
        if host.upper() != DNS_host.upper():
            msg = "ERROR: " + host + " not the same as DNS " + DNS_host
            if smtp_enabled:
                sendmail(From, To,  msg, "")
            if print_enabled:
                print(f"\r\n\n{msg}\n")
            if file_enabled:
                with open(file_name , 'a') as f:
                    f.write(f"\r\n\n{msg}\n")    

        if DNS_ip in ip_split:
            pass
        else:
            msg = "ERROR: " + ip + " not the same as DNS " + DNS_ip
            if smtp_enabled:
                sendmail(From, To,  msg, "")
            if print_enabled:
                print(f"\r\n\n{msg}\n")
            if file_enabled:
                with open(file_name , 'a') as f:
                    f.write(f"\r\n\n{msg}\n")
    try:
        if ip == '':
            ip = socket.gethostbyname(host)

        for ipdict in ipalive:
            if ipdict.get('ip') == ip:
                ipalive.remove(ipdict)
                break

        pinger = Pinger(target_host=ip, count=Count, size=Size, timeout=Timeout, debug=Debug)
        max, min, avg, los = pinger.ping()

    except:
       if Debug:
           print("%s not resolvable" % host)

    if Debug:
        print(min, max, avg, los)

    return min, max, avg, los, ip
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def PingHost(Host):

    global Count, Size, Timeout, Debug

    host = ""
    acti = ""

    if Host.find(";") != -1:
        parts = Host.split(";")
        host = parts[0].strip()
        acti = parts[2].strip()
    else:
        host = Host

    print(f"\r                                                   \r", end="", flush=True)
    print(f"\r    Host: " + host,                                     end="", flush=True)

    min, max, avg, loss, ip = doping(Host, int(Count), int(Size), int(Timeout), Debug)

    if   loss == 100 and min != int(Timeout) and acti == "A":
        msg = "ERROR: " + host.upper() + " (" + ip + ") reachability - FAILED"
        if smtp_enabled:
            sendmail(From, To, msg, "")
        if print_enabled:
            print(f"\r\n      {msg}\n")
        if file_enabled:
            with open(file_name , 'a') as f:
                f.write(f"\r\n\n{msg}\n")
    elif loss == 100 and min == int(Timeout) and acti == "A":
        msg = "ERROR: " + host.upper() + " can't be resolved to IP address - FAILED"
        if smtp_enabled:
            sendmail(From, To, msg, "")
        if print_enabled:
            print(f"\r\n      {msg}\n")
        if file_enabled:
            with open(file_name , 'a') as f:
                f.write(f"\r\n\n{msg}\n")
    elif loss == int(Count) - 1:
        msg = "ERROR: " + host.upper() + " (" + ip + ") was slow (loss = " + str(loss) + "% )"
        if smtp_enabled:
            sendmail(From, To, msg, "")
        if print_enabled:
            print(f"\r\n      {msg}\n")
        if file_enabled:
            with open(file_name , 'a') as f:
                f.write(f"\r\n\n{msg}\n")
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def scan_net_ip(network):

    global ipnet, ipa, ipu

    ipnet.clear()
    ipa.clear()
    ipu.clear()

    startIP = str(list(network.hosts())[0])
    endIP   = str(list(network.hosts())[-1])

    # Convert IP addresses to integers
    start = list(map(int, startIP.split('.')))
    end = list(map(int, endIP.split('.')))

    # Generate IP range
    for i in range(start[0], end[0] + 1):
        for j in range(start[1], end[1] + 1):
            for k in range(start[2], end[2] + 1):
                for l in range(start[3], end[3] + 1):
                    ip = f"{i}.{j}.{k}.{l}"
                    print(f"\r                          ", end="", flush=True)
                    print(f"\r      IP: " + ip,            end="", flush=True)
                    pinger = Pinger(target_host=ip, count=DEFAULT_COUNT, size=DEFAULT_SIZE, timeout=DEFAULT_TIMEOUT, debug=Debug)
                    min, max, avg, loss = pinger.ping()
                    if loss == 0:
                        ipa.append(ip)
                    else:
                        ipu.append(ip)
    print(f"\r                         \r", end="", flush=True)
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def scan_net_arp(network):
    
    global arpalive

    try:
        # Create an ARP request packet for the specified IP range.
        arp_request = ARP(pdst=str(network))
        
        # Create an Ethernet frame to broadcast the ARP request.
        # `dst="ff:ff:ff:ff:ff:ff"` is the broadcast MAC address.
        broadcast_ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        
        # Combine the Ethernet and ARP packets into one.
        # The `/` operator in Scapy layers the packets.
        arp_request_broadcast = broadcast_ether_frame / arp_request
        
        # Send the packet and capture the responses.
        # `timeout` specifies how long to wait for a response.
        # `verbose=False` suppresses Scapy's default output.
        answered_packets, unanswered_packets = srp(arp_request_broadcast, timeout=1, verbose=False)
        
        arpalive = []
        for sent, received in answered_packets:
            arpalive.append({'ip': received.psrc, 'mac': received.hwsrc})

        if Debug:
            for ap in arpalive:
                print(f" {ap['ip']:<15}    {ap['mac']}")
            else:
                print("No devices found.") 
            
        return arpalive
        
    except ImportError:
        print("Scapy is not installed. Please install it using 'pip install scapy'.")
        print("Make sure you also install Npcap from https://npcap.com/#download.")
        sys.exit(1)
        
    except Exception as e:
        return []
#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def log2lan(net):

    global PingDict, outputFile
    global host_ip, host_mac

    with open(outputFile, 'a') as f:
        l = len(ipalive)
        f.write(f"###################\n")
        f.write(f"### Net: {net}\n")
        f.write(f"###################\n\n")
        f.write(f"IPs alive ({l})\n----------------\n")
        for ipdict in ipalive:

            ip = ipdict['ip']

            # Format last part with 3 digits, padded with zeros
            ip_split = ip.split(".")
            ip_split[0] = f"{int(ip_split[0]):3d}"
            ip_split[1] = f"{int(ip_split[1]):03d}"
            ip_split[2] = f"{int(ip_split[2]):03d}"
            ip_split[3] = f"{int(ip_split[3]):03d}"
            ip_15 = ".".join(ip_split)

            # find hostname in DNS
            hostname = ipdict['hostname']
            if hostname == "":
                hostname = "<not in DNS>"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "<not in DNS>"
                    if ip_15 in PingDict:
                        hostname = PingDict[ip_15]

            
            
            mac = ipdict['mac']
            if mac == "":
                if host_ip != "":
                    if ip != host_ip:
                        # Run the arp command to get the MAC address
                        arp_command = ['arp', '-a', ip]
                        output = subprocess.check_output(arp_command).decode()
                        # Use regex to find the MAC address in the output
                        mac_address = re.search(r'(([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2})', output)
                        if mac_address:
                            mac = mac_address.group(0).replace('-', ':')
                        else:
                            mac = ""
                    else:
                        mac = host_mac
                else:
                    # Run the arp command to get the MAC address
                    arp_command = ['arp', '-a', ip]
                    output = subprocess.check_output(arp_command).decode()
                    # Use regex to find the MAC address in the output
                    mac_address = re.search(r'(([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2})', output)
                    if mac_address:
                        mac = mac_address.group(0).replace('-', ':')
                    else:
                        mac = ""

            if hostname != "" and mac != "":
                line = f"{ip_15:<15} - {hostname:<40}  {mac}"
            elif hostname != "" and mac == "":
                line = f"{ip_15:<15} - {hostname:<40}"
            elif hostname == "" and mac != "":
                line = f"{ip_15:<15} - {hostname:<40}  {mac}"
            else:
                line = f"{ip_15:<15} - {hostname:<40}  [??:??:??:??:??:??]"

            f.write(f"{line}\n")

            ipnet.append(line)

        # l = len(ipu)
        # f.write(f"\n\nIPs unused ({l})\n----------------\n")
        for ip in ipu:
            # Format last part with 3 digits, padded with zeros
            ip_split = ip.split(".")
            ip_split[0] = f"{int(ip_split[0]):3d}"
            ip_split[1] = f"{int(ip_split[1]):03d}"
            ip_split[2] = f"{int(ip_split[2]):03d}"
            ip_split[3] = f"{int(ip_split[3]):03d}"
            ip_15 = ".".join(ip_split)
            hostname = ""
            if ip_15 in PingDict:
                hostname = PingDict[ip_15]
                line = f"{ip_15:<15} - {hostname:<39}  !!!! NOT ALIVE !!!!"
            else:
                line = f"{ip_15:<15}"
            ipnet.append(line)
            # f.write(f"{line}\n")
        # f.write(f"\n\n")

        ipnet.sort(key=lambda x: x[:15])

        f.write(f"\n\nIP inventory\n----------------\n")
        for ip in ipnet:
            f.write(f"{ip}\n")
        f.write(f"\n\n")

#----------------------------------------------------------------------------------

#----------------------------------------------------------------------------------
def log2txt(net):

    global outputFile, ipa

    with open(outputFile.replace(".lan", ".txt") , 'w') as f:
        f.write(f"# Format: hostname;IP-address;Status\n")
        f.write(f"# Status can be A = Active or O = occasionally\n")
        f.write(f"################################################\n")
        f.write(f"### Internal netwerk {net}\n")
        f.write(f"################################################\n")
        f.write(f"#-----------------------------------------------\n")
        f.write(f"# Fixed IP\n")
        f.write(f"# DHCP reservations\n")
        f.write(f"# DHCP\n")
        f.write(f"#-----------------------------------------------\n\n")

        for ip in ipa:

            # find hostname in DNS
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "<not in DNS>"

            f.write(f"{hostname};{ip};A\n")

        f.write(f"\n\n")

        # some extra checks for the healty of your network
        f.write(f"################################################\n")
        f.write(f"### External netwerks\n")
        f.write(f"################################################\n")
        f.write(f"#-----------------------------------------------\n")
        f.write(f"# DNS Google\n")
        f.write(f"#-----------------------------------------------\n")
        f.write(f"dns.google;8.8.8.8;A\n")
        f.write(f"#-----------------------------------------------\n")
        f.write(f"# DNS OpenDNS\n")
        f.write(f"#-----------------------------------------------\n")
        f.write(f"dns.umbrella.com;208.67.222.222;A\n")
        f.write(f"#-----------------------------------------------\n")
        f.write(f"# DNS EU\n")
        f.write(f"#-----------------------------------------------\n")
        f.write(f"protective.joindns4.eu;86.54.11.1;A\n")
        f.write(f"child-noads.joindns4.eu;86.54.11.11;A\n")
        f.write(f"child.joindns4.eu;86.54.11.12;A\n")
        f.write(f"noads.joindns4.eu;86.54.11.13;A\n")
        f.write(f"unfiltered.joindns4.eu;86.54.11.100;A\n")
        f.write(f"\n\n")

#----------------------------------------------------------------------------------


#----------------------------------------------------------------------------------
def get_mac_address_and_hostname(ip_address):

    mac_address = None
    hostname = None

    try:
        process = subprocess.Popen(['arp', '-a', ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        output = stdout.decode()
        lines = output.splitlines()
        for line in lines:
            if ip_address in line:
                parts = line.split()
                if len(parts) >= 2:
                    # Windows uses hyphens, convert to colons
                    mac_address = parts[1].replace("-", ":")
                    break

        try:
            hostname = socket.gethostbyaddr(ip_address)[0]

        except socket.herror:
            hostname = None

    except:
        return None, None

    return mac_address, hostname
#----------------------------------------------------------------------------------

###################################################################################
### Main
###################################################################################

if __name__ == "__main__":

    print(f"{strScriptBase} Version: {VERSION} written by Marc Engrie\n")
    print(f"  running on {COMPUTERNAME} with IP ")
    netifs=netifaces.interfaces()
    for netif in netifs:
        netifaddr = netifaces.ifaddresses(netif)
        if netifaces.AF_INET in netifaddr:
            ip = netifaddr[netifaces.AF_INET][0]["addr"]
            mask = netifaddr[netifaces.AF_INET][0]["netmask"]
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            print(f"    IP: {ip:<15}  Netmask: {mask:<15}  Network: {network}")
    print("")

    # Load config from a YAML file
    with open(yamlFilename, 'r') as file:
        config = yaml.safe_load(file)

    # Accessing values
    print_enabled = config['PRINT']['Enabled']
    smtp_enabled  = config['SMTP']['Enabled']
    file_enabled  = config['FILE']['Enabled']

    if smtp_enabled:
        smtp_config = config['SMTP']
        smtpserver  = smtp_config['Server']
        smtpport    = smtp_config['Port']
        smtptls     = smtp_config['TLS']
        smtpCA      = smtp_config['CA']
        smtplogin   = smtp_config['Login']
        smtppass    = smtp_config['Password']
        From        = strScriptBase + "." + COMPUTERNAME + "@" + smtp_config['MailDomain']
        To          = smtp_config['To']
        if Debug:
            sendmail(From, To, 'Testmail',"")
            
    # get command line arguments
    getargs(sys.argv[1:])

    ## delete outputfile, if exists
    if os.path.exists(outputFile):
        os.remove(outputFile)

    if PingList == "":
        if os.path.exists(outputFile.replace(".lan", ".txt")):
            os.remove(outputFile.replace(".lan", ".txt"))        

    if file_enabled:
        file_name = outputFile.replace(".lan", ".err")
        if os.path.exists(file_name):
            os.remove(file_name)        

    # init some vars
    addr_lst = []
    mask_lst = []
    startIP  = ""
    endIP    = ""

    # check if one of host interface is within IP_NET
    netifs=netifaces.interfaces()
    for netif in netifs:
        netifaddr = netifaces.ifaddresses(netif)
        if netifaces.AF_INET in netifaddr:
            ip   = netifaddr[netifaces.AF_INET][0]["addr"]
            mask = netifaddr[netifaces.AF_INET][0]["netmask"]
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            if str(network).startswith(IP_NET):
                # print(f"  {COMPUTERNAME} with IP {ip} within network {network}")
                host_ip   = netifaddr[netifaces.AF_INET][0]["addr"]
                host_mac  = netifaddr[netifaces.AF_LINK][0]['addr'].upper()
                host_net  = True
                addr_lst  = ip.split('.')
                mask_lst  = mask.split('.')
                break
            else:
                if Debug:
                    print(f"    Found local Net {ip:<15} -->> skipping this network")

    ## ---------------------------------------------------------------------------------------------------------------------------
    ## scan requested network entirely
    ## ---------------------------------------------------------------------------------------------------------------------------

    if len(mask_lst) == 0 and IP_MASK != "":
        print(f"  Full Ping scan ({IP_NET} - {IP_MASK})")
        network = extend_ip(IP_NET, IP_MASK)
        if Debug:
            print(f"Extended IP: {network.network_address}")
            print(f"Network: {network}")
        print(f"    Network {network} is a routed network.")
        host_ip  = ""
        host_mac = ""
        host_net = False
    else:
        print(f"  Full Ping scan ({IP_NET} - {mask})")
        print(f"    Network {network} is a non-routed network.")

    startIP = str(list(network.hosts())[0])
    endIP   = str(list(network.hosts())[-1])

    print(f"      Scanning from {startIP} to {endIP}")

    scan_net_ip(network)
    
    for ip in ipa:
        ipalive.append({'ip': ip, 'hostname': '', 'mac': ''})
        
    # only do arp scan if within same segement = non-routed 
    if host_net:
        scan_net_arp(network)
        
        # Iterate through ipalive and update mac if ip matches
        if len(arpalive) > 0:
            for ipdict in ipalive:
                ip_val = ipdict['ip']
                for apdict in arpalive:
                    if apdict['ip'] == ip_val:
                        ipdict['mac'] = apdict['mac']
                        arpalive.remove(apdict)
                        break

        if Debug:
            print("Updated ipalive:")
            print(ipalive)

            print("Remaining arpa:")
            print(arpa)

        for apdict in arpalive:
            ip  = apdict['ip']
            mac = apdict['mac']
            ipalive.append({'ip': ip, 'hostname': '', 'mac': mac})

    log2lan(IP_NET)

    ## ---------------------------------------------------------------------------------------------------------------------------
    ## ping devices based on list
    ## ---------------------------------------------------------------------------------------------------------------------------

    if PingList != "":
        with open(PingList, "r") as fh:
            for line in fh:
                Host = line.strip()
                if len(Host) > 0:
                    if Host[0] != '#':
                        PingHost(Host.strip())
        print(f"\r                                                  \r", end="", flush=True)

    else:
        log2txt(IP_NET)

    # ## ---------------------------------------------------------------------------------------------------------------------------
    # ## did we forget hosts;ips???
    # ## ---------------------------------------------------------------------------------------------------------------------------

    if len(ipalive) > 0 and PingList != "":
        body = ""
        for ipdict in ipalive:
            ip       = ipdict['ip']
            hostname = ipdict['hostname']
            mac      = ipdict['mac']

            MAC_host, DNS_host = get_mac_address_and_hostname(ip)
            
            if hostname == "":
                if DNS_host:
                    hostname = DNS_host.replace(".home","").lower()

            if mac == "":
                if MAC_host:
                    mac = MAC_host.upper()

            body = body + "IP address: {0:} - Hostname: {1:} - MAC address: {2:}\n".format(ip.ljust(16), hostname.ljust(20), mac.ljust(16))

        msg = "Not listed active IPs\n"
        if smtp_enabled:
            sendmail(From, To,  msg, body)
        if print_enabled:
            print(f"\r\n\n    {msg}\n")
            for line in body.split("\n"):
                print(f"      {line}")
        if file_enabled:
            with open(file_name , 'a') as f:
                f.write(f"\r\n\n    {msg}\n")
                for line in body.split("\n"):
                    f.write(f"      {line}")
                    
    sys.exit(0)
