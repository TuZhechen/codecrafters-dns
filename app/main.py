from app.dns import Header, Question, Answer, Message
from typing import List
import socket
import traceback
import argparse
import sys
import asyncio

async def handle_query(data: bytes, client_addr: tuple[str, int], server_socket: socket.socket, resolver_addr=None) -> None:
    try:
        # Parse the header
        header = Header.from_bytes(data)

        # Parse multiple questions (starting after header)
        questions = []
        offset = 12
        for _ in range(header.num_questions):
            question, offset = Question.from_bytes(data, offset)
            questions.append(question)
        
        answers = []
        if resolver_addr:
            resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for question in questions:
                answer = await forward_query(resolver_socket, resolver_addr, question)
                if answer:
                    answer.name = question.encode_name()
                answers.append(answer)
        else:
            for question in questions:
                answer = Answer(
                    name=question.encode_name(),
                    type_=question.type_,
                    class_=question.class_,
                    ttl=60,
                    data=socket.inet_aton('8.8.8.8')
                )
                answers.append(answer)
        
        response_msg = Message(
            header=Header(
                id=header.id,
                qr=1,
                opcode=header.opcode,
                aa=0,
                tc=0,
                rd=header.rd,
                ra=1 if resolver_addr else 0,
                z=0,
                rcode=0 if header.opcode == 0 else 4,
                num_questions=len(questions),
                num_answers=len(answers),
                num_authorities=0,
                num_additionals=0
            ),
            questions=questions,
            answers=answers
        )
        await server_socket.sendto(response_msg.to_bytes(), client_addr)

    except Exception as e:
        print(f"Error handling query: {e}")
        print(f"Stack trace:", traceback.format_exc())

def forward_query(resolver_socket: socket.socket, resolver_addr: tuple[str, int], question: Question) -> Answer:
    # Create single-question query
    query = Message(
        header=Header(
            id=1234,
            qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0,
            num_questions=1,
            num_answers=0,
            num_authorities=0,
            num_additionals=0
        ),
        questions=[question],
        answers=[]
    )
    
    # Forward to resolver
    resolver_socket.sendto(query.to_bytes(), resolver_addr)
    response_data, _ = resolver_socket.recvfrom(512)
    
    # Parse response
    response = Message.from_bytes(response_data)
    return response.answers[0] if response.answers else None

def main():
    HOST = "127.0.0.1"
    PORT = 2053
    BUFFER_SIZE = 512

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, PORT))

    # Parse arguments if resolver is provided
    resolver_addr = None
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument('--resolver', help='DNS resolver address <ip:port>')
        args = parser.parse_args()
        if args.resolver:
            resolver_ip, resolver_port = args.resolver.split(':')
            resolver_addr = (resolver_ip, int(resolver_port))

    # Create resolver socket if needed
    resolver_socket = None
    if resolver_addr:
        resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        while True:
            buf, source = udp_socket.recvfrom(BUFFER_SIZE)
            asyncio.create_task(handle_query(buf, source, udp_socket, resolver_addr))
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        udp_socket.close()
        if resolver_socket:
            resolver_socket.close()

if __name__ == "__main__":
    main()
