from dataclasses import dataclass
from typing import List
import struct

@dataclass
class Header:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    num_questions: int
    num_answers: int
    num_authorities: int
    num_additionals: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Header':
        id, flags, num_questions, num_answers, num_authorities, num_additionals = struct.unpack("!6H", data[:12])
        
        # Extract individual flags from the 16-bit flags field
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 0x1
        tc = (flags >> 9) & 0x1
        rd = (flags >> 8) & 0x1
        ra = (flags >> 7) & 0x1
        z = (flags >> 4) & 0x7
        rcode = flags & 0xF

        return cls(id, qr, opcode, aa, tc, rd, ra, z, rcode, num_questions, num_answers, num_authorities, num_additionals)
    
    def to_bytes(self) -> bytes:
        # Construct the 16-bit flags field from individual flags
        flags = (
            (self.qr << 15) |
            (self.opcode << 11) |
            (self.aa << 10) |
            (self.tc << 9) |
            (self.rd << 8) |
            (self.ra << 7) |
            (self.z << 4) |
            self.rcode
        )

        return struct.pack(
            "!6H",
            self.id,
            flags,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals
        )

@dataclass
class Question:
    name: bytes
    type_: int
    class_: int

    @classmethod
    def from_bytes(cls, buf: bytes, offset: int) -> tuple['Question', int]:
        name, offset = cls.parse_name(buf, offset)
        type_, class_ = struct.unpack("!2H", buf[offset:offset + 4])
        return cls(name=name, type_=type_, class_=class_), offset + 4

    def to_bytes(self) -> bytes:
        return self.encode_name() + struct.pack("!2H", self.type_, self.class_)
    
    @staticmethod
    def parse_name(buf: bytes, offset: int) -> tuple[bytes, int]:
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

    def encode_name(self) -> bytes:
        '''Encode domain name for DNS message'''
        parts = self.name.split(b'.')
        return b''.join(len(part).to_bytes(1, 'big') + part for part in parts) + b'\x00'

@dataclass
class Answer:
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
class Message:
    header: Header
    questions: List[Question]
    answers: List[Answer]
   
    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + b''.join(q.to_bytes() for q in self.questions) + b''.join(a.to_bytes() for a in self.answers) 