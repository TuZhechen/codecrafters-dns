import socket
from dnslib import DNSRecord, RR, QTYPE

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            query = DNSRecord.parse(buf)
            response = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)
            response.add_answer(RR(query.q.qname, QTYPE.A, rdata='1.2.3.4'))
            udp_socket.sendto(response.pack(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
