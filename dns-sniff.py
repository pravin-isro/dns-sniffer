import socket
import struct
import textwrap
from scapy.all import DNS

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '


DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame (raw_data)
        #print('\n ETHERNET FRAME:')
       # print(TAB_1+ 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        
        if eth_proto==8:  
            (version, header_length, ttl ,proto, src, target, data) = ipv4_packet(data)
         #  print(TAB_1+ 'Ipv4 PACKET:')
          #  print(TAB_2+ 'Version: {}, Header_length: {}, TTL: {}'.format(version, header_length, ttl))
             
           # print(TAB_2+ 'PROTOCOL: {}, SRC_IP: {}, DEST_IP: {}'.format(proto, src, target))
              
            if proto == 17:
                  (src_port, dest_port, size, data) = udp_segment(data)
                  if dest_port == 53 :
                  # print(TAB_1+ 'UDP Segment--------------------------------------')   
                #  print(TAB_2+ 'SRC_PORT: {}, DEST_PORT: {}, Length: {}'.format(src_port, dest_port, size))   
                   #print(data)
                   print(TAB_1+ 'UDP_DNS')
                   
                   data_1= DNS(data)
                   data_1.show()  
                   #hex_string= str(data)
                   #hex_string_1 = hex_string.replace("\"," ") 
                  # bytes_object = bytes.fromhex(hex_string)
                   #ascii_str= bytes_object.decode("ASCII")               
                   #print(ascii_str)
                   #print(hex_string_1)
                #  ascii_string = data[1:2].decode("ASCII")
                 # print(ascii_string)
              #    hex_string = data
               #   bytes_object = bytes.fromhex(hex_string)
                  
                  #print(data[:4])
                  #print(format_multi_line(DATA_TAB_3, data))
                 #icmp_type, code, checksum= icmp_packet(data)
                 #print(TAB_1+ 'ICMP PACKET:')
                 #print(TAB_2+ 'Type: {}, Code: {}, Checksum: {}'.format( icmp_type, code, checksum))
                 #print(format_multi_line(DATA_TAB_3, data))
                 
            #elif proto == 6:
             #  (src_port, dest_port, sequence, acknowledgement, off, data)= tcp_segment(data)
              # if dest_port == 53: 
               #   print(TAB_1+ 'TCP_DNS')
              #  print(TAB_2+ 'SRC_PORT: {}, DEST_PORT {}'.format(src_port, dest_port))
                #  print(str(data))
                   
            #elif proto == 17:
                  
                   
                    
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto),data[14:]




def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl ,proto, ipv4(src), ipv4(target), data[header_length:]
    
    
def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]
    
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserve_flag) = struct.unpack('!  H L L H H', data[:14])
    offset = (offset_reserve_flag >>12) * 4
    flags_urg = (offset_reserve_flag & 32) >> 5   
    flags_ack = (offset_reserve_flag & 16) >> 4 
    flags_psh = (offset_reserve_flag & 8) >> 3
    flags_rst = (offset_reserve_flag & 4) >> 2 
    flags_syn = (offset_reserve_flag & 2) >> 1 
    flags_fin = (offset_reserve_flag & 1) 
    return(src_port, dest_port, sequence, acknowledgement, flags_urg, flags_ack, flags_psh, flags_rst, flags_syn, flags_fin, data[offset:]) 
    
    
def udp_segment(data):
   src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
   return src_port, dest_port, size, data[8:]
    
    
def format_multi_line(prefix, string, size=80):
   size -= len(prefix)
   if isinstance(string, bytes):
       string= ''.join(r'\x{:02x}'.format(byte) for byte in string)
       if size % 2 :
         size -= 1 
   return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
    
    
    
    

main()

