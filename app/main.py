import socket
import struct

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            #Unpack the DNS query header
            id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])

            #Create a DNS response header
            response = struct.pack('!6H', id, 0x8180, qdcount, 1, 0, 0) + buf[12:] + buf[12:-4]
            response += struct.pack('!2H', 1, 0X0001) # TYPE and CLASS
            response += struct.pack('!I', 3600) # TTL
            response += struct.pack('!H', 4) # RDLENGTH
            response += socket.inet_aton("1.2.3.4") # RDATA

            #Send the DNS response
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
