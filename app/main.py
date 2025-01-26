from app.dns import Header, Question, Answer, Message
from typing import List
import socket
import traceback

def main():
    HOST = "127.0.0.1"
    PORT = 2053
    BUFFER_SIZE = 512

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, PORT))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(BUFFER_SIZE)
            
            # Parse the header
            header = Header.from_bytes(buf)
            
            # Parse question (starting after header)
            question, _ = Question.from_bytes(buf, 12)

            # Prepare response header
            response_header = Header(
                id = header.id,
                qr = 1,
                opcode = header.opcode,
                aa = 0,
                tc = 0,
                rd = header.rd,
                ra = 0,
                z = 0,
                rcode = 0 if header.opcode == 0 else 4,
                num_questions = 1,
                num_answers = 1,
                num_authorities = 0,
                num_additionals = 0
            )

            # Compose answer
            answer = Answer(
                name = question.encode_name(),
                type_ = question.type_,
                class_ = question.class_,
                ttl = 100,
                data = socket.inet_aton('8.8.8.8')
            )
            
            # Create response message
            response_msg = Message(
                header = response_header,
                questions = [question],
                answers = [answer]
            )
                        
            # Convert to bytes and send
            udp_socket.sendto(response_msg.to_bytes(), source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            print(f"Stack trace:", traceback.format_exc()) 
            break

if __name__ == "__main__":
    main()
