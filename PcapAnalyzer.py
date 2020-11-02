from scapy.all import *
import os


class PcapAnalyzer():
    def __init__(self):
        self.pcap_list = []

    def analyzePcap(self, filepath):

        print('filepath:' + filepath)
        s1 = PcapReader(filepath)
        icmp_list = []
        self.pcap_list.append(icmp_list)
        No = 1

        try:
            # data 是以太网 数据包
            data = s1.read_packet()

            while data is not None:
                
                icmp_list.append(data.payload.payload.payload.original)
                data = s1.read_packet()

                No += 1

            s1.close()
        except EOFError as ex:
            print(filepath)
            print(No)
            print(ex)
        
    def get_filelist(self, dir):

        if os.path.isfile(dir):
            try:
                self.analyzePcap(dir)
            except Scapy_Exception as e:
                print(e)

        elif os.path.isdir(dir):
            for s in os.listdir(dir):
                newDir = os.path.join(dir, s)
                self.get_filelist(newDir)