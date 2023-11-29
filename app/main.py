import socket
import struct

def parse_name(buf, offset):
    labeks = []
    while True:
        length = buf[offset]
        if length == 0:
            break
        labels.append(buf[offset + 1: offset + 1 + length].decode)
        offset += 1 + length
    return ".".join(labels), offset

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Unpack the DNS query header
            id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])

            # Parse the question section
            qname, offset = parse_name(buf, 12)
            qtype, qclass = struct.unpack("!2H", buf[offset:offset + 4])

            # Add the question section
            name = b''.join(struct.pack("B", len(label)) + label.encode() for label in qname.split(".")) + b'\x00'
            qtype = struct.pack("!H", 1)
            qclass = struct.pack("!H", 1)
            question = name + qtype + qclass

            # Create a DNS response
            response = struct.pack('!6H', id, (flags & 0x0100) | 0x8000, qdcount, 1, nscount, arcount)
            response += question
            response += name
            response += struct.pack('!2H', 1, 0X0001) # TYPE and CLASS
            response += struct.pack('!I', 60) # TTL
            response += struct.pack('!H', 4) # RDLENGTH
            response += socket.inet_aton("8.8.8.8") # RDATA

            #Send the DNS response
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
