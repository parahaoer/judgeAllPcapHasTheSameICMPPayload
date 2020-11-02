from PcapAnalyzer import PcapAnalyzer


def judgeAllPcapHasTheSameICMPPayload(pcap_list, timestamp_len):

    for pcap_j in range(0, len(pcap_list)-1):
        for icmp_i in range(0, len(pcap_list[pcap_j])):
            icmp_payload_j_i = pcap_list[pcap_j][icmp_i]
            icmp_payload_j_1_i = pcap_list[pcap_j+1][icmp_i]
            if(len(icmp_payload_j_i) == timestamp_len):
                continue
            elif(len(icmp_payload_j_i) != len(icmp_payload_j_1_i)):
                if timestamp_len == 8:
                    print("problem comes: linux32 has problem," + "the " + str(pcap_j) + " file," + "the " + str(icmp_i) + "packet," + "icmp_payload_j_i:" + str(len(icmp_payload_j_i)) + "," + str(len(icmp_payload_j_1_i)))
                elif timestamp_len == 16:
                    print("problem comes: linux64 has problem," + "the " + str(pcap_j) + " file," + "the " + str(icmp_i) + "packet," + "icmp_payload_j_i:" + str(len(icmp_payload_j_i)) + "," + str(len(icmp_payload_j_1_i)))
            
            elif(len(icmp_payload_j_i) > timestamp_len):
                for i in range(timestamp_len-1, len(icmp_payload_j_i)):
                    if(icmp_payload_j_i[i] != icmp_payload_j_1_i[i]):
                        print("has problem")
            
            elif(len(icmp_payload_j_i) < timestamp_len):
                for i in range(0, len(icmp_payload_j_i)):
                    if(icmp_payload_j_i[i] != icmp_payload_j_1_i[i]):
                        print("has problem")


if __name__ == "__main__":
    
    pcapAnalyzer = PcapAnalyzer()
    pcapAnalyzer.get_filelist('pcap_dir/linux32')
    pcap_list = pcapAnalyzer.pcap_list
    judgeAllPcapHasTheSameICMPPayload(pcap_list, 8)

    # pcapAnalyzer = PcapAnalyzer()
    # pcapAnalyzer.get_filelist('pcap_dir/linux64')
    # pcap_list = pcapAnalyzer.pcap_list
    # judgeAllPcapHasTheSameICMPPayload(pcap_list, 16)





