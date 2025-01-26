from dataclasses import dataclass
from typing import List
import socket
import struct

def parse_name(buf, offset):
    '''parse domain name from DNS query'''
    labels = []
    while True:
        length = buf[offset]
        if length == 0:
            offset += 1  # Move past the 0 length byte
            break
        labels.append(buf[offset + 1:offset + 1 + length].decode('utf-8'))
        offset += 1 + length
    return b'.'.join(label.encode('utf-8') for label in labels), offset

@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int
    num_answers: int
    num_authorities: int
    num_additionals: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'DNSHeader':
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
        return cls(id, flags, qdcount, ancount, nscount, arcount)
    
    def to_bytes(self) -> bytes:
        return struct.pack(
            "!6H",
            self.id,
            self.flags,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals
        )

@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int

    @classmethod
    def from_bytes(cls, buf: bytes, offset: int) -> tuple['DNSQuestion', int]:
        name, offset = parse_name(buf, offset)
        type_, class_ = struct.unpack("!2H", buf[offset:offset + 4])
        return cls(name=name, type_=type_, class_=class_), offset + 4

    def to_bytes(self) -> bytes:
        return self.name + struct.pack("!2H", self.type_, self.class_)

@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes

    def to_bytes(self) -> bytes:
        return (
            self.name +
            struct.pack("!2H", self.type_, self.class_) +
            struct.pack("!I", self.ttl) +
            struct.pack("!H", len(self.data)) +
            self.data
        )

@dataclass
class DNSMessage:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]

    @classmethod
    def create_response(cls, request_id: int, question: DNSQuestion) -> 'DNSMessage':
        header = DNSHeader(
            id=request_id,
            flags=0x8000,  # Standard response
            num_questions=1,
            num_answers=1,
            num_authorities=0,
            num_additionals=0
        )
        
        answer = DNSRecord(
            name=question.name,
            type_=1,  # A record
            class_=1,  # IN class
            ttl=60,
            data=socket.inet_aton("8.8.8.8")
        )
        
        return cls(header=header, questions=[question], answers=[answer])
    
    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + b''.join(q.to_bytes() for q in self.questions) + b''.join(a.to_bytes() for a in self.answers)

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            # Parse the header
            header = DNSHeader.from_bytes(buf)
            
            # Parse question (starting after header)
            question, _ = DNSQuestion.from_bytes(buf, 12)
            
            # Create response message
            response_msg = DNSMessage.create_response(header.id, question)
            
            # Debug: Print the response message details
            print("Response Header:", response_msg.header)
            print("Response Question:", response_msg.questions)
            print("Response Answer:", response_msg.answers)
            
            # Convert to bytes and send
            udp_socket.sendto(response_msg.to_bytes(), source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
