from PcapAnalyzer import PcapAnalyzer


def detectPattern(icmp_payload, time_bytes_len):

    payload_len = len(icmp_payload)
    if(payload_len >= time_bytes_len and payload_len <= time_bytes_len+2):
        return 0

    if payload_len < time_bytes_len:
        i = 0
        j = 1
    else:
        i = time_bytes_len
        j = time_bytes_len + 1
    while(j < payload_len and icmp_payload[i] != icmp_payload[j]):
        j = j + 1
    
    if j < payload_len and icmp_payload[i] == icmp_payload[j]:
        p_len = j - i
    else:
        p_len = 0

    if(p_len > 16):
        return 0
    else:

        while(j < payload_len):
            if(icmp_payload[i] != icmp_payload[j]):
                return 0
            
            i = i + 1
            j = j + 1

        return p_len
    
    
def getPattern(icmp_payload, time_bytes_len):
    p_len = detectPattern(icmp_payload, time_bytes_len)

    if(p_len != 0):
        if(len(icmp_payload) > time_bytes_len):
            r = time_bytes_len % p_len
            left = time_bytes_len
            right = left + p_len
            m = left + p_len - r
            pattern = icmp_payload[m:right] + icmp_payload[left: m]
            
        else:
            pattern = icmp_payload[0: p_len]
        
        return pattern.hex()

    return ""


if __name__ == "__main__":
    pcapAnalyzer = PcapAnalyzer()
    pcapAnalyzer.get_filelist('pcap_dir/linux32/Centos_5.5_32(2.100).pcapng')
    pcap_list = pcapAnalyzer.pcap_list 
    ftxt = open('output/output.txt', 'w', encoding="utf-8")
    for pcap_j in range(0, len(pcap_list)):
        for icmp_i in range(0, len(pcap_list[pcap_j])):
            icmp_payload_j_i = pcap_list[pcap_j][icmp_i]
            pattern = getPattern(icmp_payload_j_i, 8)
            if pattern != "":
                print(icmp_payload_j_i.hex() + "存在pattern， pattern字符串为：" + pattern)
                ftxt.write(icmp_payload_j_i.hex() + "存在pattern， pattern字符串为：" + pattern + "\n")
            else:
                print(icmp_payload_j_i.hex() + "不存在pattern")
                ftxt.write(icmp_payload_j_i.hex() + "不存在pattern" + "\n")
    
    ftxt.close()
    
