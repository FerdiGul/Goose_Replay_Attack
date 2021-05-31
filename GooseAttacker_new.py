#!/usr/bin/python
# -*- coding: utf-8 -*-

from scapy.all import *
import os
import socket
import sys
import pyshark
import time
import threading

def inputValues():
    interface = input("Enter interface name in used: ");
    #print(type(interface))
    #senderMac = input("Enter sender MAC Address[FORMAT->XX:XX:XX:XX:XX:XX]: ");
    return interface

def replayGooseTraffic(interface):
    
    #print(interface + " " + senderMac)
    pcap_file = input("Enter the saved pcap file without extension: ");
    start= time.time()
    #decoded = pyshark.FileCapture(pcap_file + ".pcap")
    #print(decoded[0]);
    traffic = rdpcap(pcap_file + '.pcap');
    #print(traffic)

    for frame in traffic:
            
        if frame.haslayer(Ether) == 1 or frame.haslayer(Dot1Q) == 1 or frame.haslayer(Raw) == 1:
        #print(frame) #that can use to create payload from real traffic
            sendp(frame, iface = interface);
            time.sleep(0.01)
            end = time.time()
    #print("Runtime :", (end-start))
    #print("Active Thread Number: ", threading.activeCount())
          
#def MMS_replay():

#def sav_replay():

def payload(interface):

    start = time.time()
    content = Ether() # header content
    content.src = "00:0c:29:d2:27:ad"
    content.dst = "01:0c:cd:01:00:00" 
    content.type = 0x8100 #802.1q tagi ETHER TYPE - HEXADECIMAL
  
    # VLAN HEADER  0x88b8 -> GOOSE protocol type
    VLAN = Dot1Q()
    VLAN.prio = 4
    VLAN.id = 0
    VLAN.vlan = 0
    VLAN.type = 0x88b8

    # GOOSE MESSAGE
    message = Raw()
    #in python2.7 it's enough -> a = '\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$FGX\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00'
    message.load = b"\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$FGX\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00"
    #print(type(message.load))
    

    #show packet parts
    ls(VLAN)
    ls(message)
    ls(content)
    #interface = input("\n enter interface:")
    new_Goose_Frame = content/VLAN/message
    #del new_Goose_Frame[header_VLAN].chksum
    print(new_Goose_Frame)
    sendp(new_Goose_Frame, iface = interface,verbose=0)
    time.sleep(0.01)
    end = time.time()
    #print("runtime: ", (end-start))
    #print("Active Thread Number: ", threading.activeCount()) # If you want to see a number of threads

if __name__ == '__main__':
    interface = inputValues()
    key=input("Enter that what you want?:\n[1]: send pcap frame\n[2]: send frame payload\n");
    if key == "1":        
        threading.Thread(target=replayGooseTraffic,args=(interface,)).start() #threading part when you wanna get min runtime. If scripts will improve in project, maybe we can use it.
    elif key == "2":
        threading.Thread(target=payload,args=(interface,)).start()
        #payload(interface)
    else:
        print("check your selection!")

#in futurework: send payload in randomly...
