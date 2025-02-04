from dataclasses import dataclass
from typing import List
from collections import OrderedDict
from time import time
import struct
        
@dataclass
class Header:
    id: int
    qr: int     # Query: 0 / Response: 1
    opcode: int # Standard query: 0 / otherwise: 1
    aa: int     # Authoritative Answer (1 if authoritative)
    tc: int     # Truncated: 1 / Not truncated: 0
    rd: int     # Recursion Desired: 1 / otherwise: 0
    ra: int     # Recursion Available: 1 / otherwise: 0
    z: int      # Reserved for future use
    rcode: int  # Response code (0 for no error)
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
        '''Parse domain name from DNS query, handling both compressed and uncompressed names'''
        labels = []
        
        while True:
            length = buf[offset]
            
            # Handle compression (first 2 bits are 11)
            if length & 0xC0 == 0xC0:
                # Extract pointer from 14 bits (clear first 2 bits and combine with next byte)
                pointer = ((length & 0x3F) << 8) | buf[offset + 1]
                next_offset = offset + 2
                # Recursively parse the name at the pointer position
                pointed_name, _ = Question.parse_name(buf, pointer)
                if labels:
                    return b'.'.join(labels) + b'.' + pointed_name, next_offset
                return pointed_name, next_offset
                
            # End of name
            if length == 0:
                offset += 1  # Move past the 0 length byte
                break
                
            # Regular uncompressed label
            label = buf[offset + 1:offset + 1 + length]
            labels.append(label)
            offset += 1 + length
        
        return b'.'.join(labels), offset

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
    
    @classmethod
    def from_bytes(cls, buf: bytes, offset: int) -> tuple['Answer', int]:
        '''Parse answer from DNS response'''
        name, offset = Question.parse_name(buf, offset)
        type_, class_, ttl, data_len = struct.unpack("!2HIH", buf[offset:offset + 10])
        data = buf[offset + 10:offset + 10 + data_len]
        return cls(name=name, type_=type_, class_=class_, ttl=ttl, data=data), offset + 10 + data_len

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
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Message':
        header = Header.from_bytes(data)
        offset = 12
        
        questions = []
        for _ in range(header.num_questions):
            question, offset = Question.from_bytes(data, offset)
            questions.append(question)
            
        answers = []
        for _ in range(header.num_answers):
            answer, offset = Answer.from_bytes(data, offset)
            answers.append(answer)
            
        return cls(header=header, questions=questions, answers=answers)

class DNSCache:
    def __init__(self, capacity: int = 1000):
        self.cache = OrderedDict()
        self.capacity = capacity
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Answer:
        if key not in self.cache:
            self.misses += 1
            return None
        
        answer = self.cache[key]
        self.cache.move_to_end(key)
        self.hits += 1
        return answer
        
    def put(self, key: tuple, answer: Answer):
        if len(self.cache) >= self.capacity:
            self.cache.popitem(last=False)
            
        self.cache[key] = answer
        
    def clear(self):
        self.cache.clear()
        self.hits = 0
        self.misses = 0
        
    def stats(self) -> dict:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": self.hits / (self.hits + self.misses) if self.hits + self.misses > 0 else 0,
            "cache_size": len(self.cache),
            "cache_capacity": self.capacity
        }
        