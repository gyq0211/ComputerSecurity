# !/usr/bin/python3

from scapy.all import *
import pcapy
import argparse
import base64
from scapy.layers.inet import TCP

HTTP = lambda protocol: protocol in {80}
NIKTO = lambda payload: 'nikto' in payload or 'Nikto' in payload or 'NIKTO' in payload

globalAlertID = 0
count = 0
user = ""
password = ""
FTP_user = ""
FTP_pass = ""


def getIP(p):
    if p.haslayer(IP):
        return p[IP].src
    else:
        return 'no IP'


def print_alarm(scan_type, ip, protocol):
    global globalAlertID
    globalAlertID += 1
    print('ALERT #%d: %s from %s (%s)!' % (globalAlertID, scan_type, ip, protocol))


def print_alarm2(scan_type, ip, protocol, user, username, passw, password):
    global globalAlertID
    globalAlertID += 1
    print('ALERT #%d: %s from %s (%s) (%s%s, %s%s)' % (
        globalAlertID, scan_type, ip, protocol, user, username, passw, password))


def pass_http(p):
    global password
    global user
    load_text = p[Raw].load
    if HTTP(p[TCP].sport) or HTTP(p[TCP].dport):
        for line in str(load_text, 'utf-8').split('\r'):
            if 'Authorization: Basic' in line:
                user_pass = line[len('Authorization: Basic'):]
                try:
                    user_pass = base64.b64decode(user_pass[1:])
                    user_pass = str(user_pass, 'utf-8')
                    user = user_pass[:user_pass.find(':')]
                    password = user_pass[user_pass.find(':'):]
                except:
                    pass
                print_alarm2('Usernames and passwords sent in-the-clear', getIP(p), 'HTTP', 'username:', user,
                             'password',
                             password)
                break


def pass_ftp(p):
    global count
    global FTP_pass
    global FTP_user
    load_text = str(p.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    if load_text.find('USER') != -1:
        flag = False
        for i in load_text:
            if i == " ":
                flag = True
            if flag and i != " ":
                if i == '"':
                    break
                FTP_user += i
    elif 'PASS' in load_text:
        flag = False
        for i in load_text:
            if i == " ":
                flag = True
            if flag and i != " ":
                if i == '"':
                    break
                FTP_pass += i
    else:
        if load_text.find('230') != -1:
            count += 1
            print_alarm2('Usernames and passwords sent in-the-clear', getIP(p), 'FTP', 'username:', FTP_user,
                         'password',
                         FTP_pass)


def packetcallback(packet):
    try:
        if TCP in packet:
            if packet[TCP].flags == "FPU":
                print_alarm('XMAS scan is detected', getIP(packet), 'TCP')
            if packet[TCP].flags == "F":
                print_alarm('FIN scan is detected', getIP(packet), 'TCP')
            if packet[TCP].flags == "":
                print_alarm('NULL scan is detected', getIP(packet), 'TCP')
            elif packet.haslayer(TCP):
                if NIKTO(str(packet)):
                    print_alarm('NIKTO scan is detected', getIP(packet), 'TCP')
        if packet.haslayer(TCP):
            if packet[TCP].sport == 21 or packet[TCP].dport == 21:
                pass_ftp(packet)
        if packet[TCP].dport == 80:
            pass_http(packet)
        if packet[TCP].sport == 3389 or packet[TCP].dport == 3389:
            print_alarm('Someone scanning for RDP is detected', getIP(packet), 'TCP')
    except:
        pass


parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
    try:
        print("Reading PCAP file %(filename)s..." % {"filename": args.pcapfile})
        # sniff(offline=args.pcapfile, prn=packetcallback)
        r = rdpcap(args.pcapfile)
        for pkt in r:
            packetcallback(pkt)
    except:
        print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename": args.pcapfile})
else:
    print("Sniffing on %(interface)s... " % {"interface": args.interface})
    try:
        sniff(iface=args.interface, prn=packetcallback)
    except pcapy.PcapError:
        print(
            "Sorry, error opening network interface %(interface)s. It does not exist." % {"interface": args.interface})
    except:
        print("Sorry, can\'t read network traffic. Are you root?")
