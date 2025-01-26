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
            print(f"Received header: {header}")
            
            offset = 12
            
            # Parse multiple questions (starting after header)
            questions = []
            num_questions = header.num_questions
            while num_questions > 0:
                question, offset = Question.from_bytes(buf, offset)
                questions.append(question)
                num_questions -= 1
            print(f"Parsed questions: {questions}")

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
                num_questions = len(questions),
                num_answers = len(questions),
                num_authorities = 0,
                num_additionals = 0
            )
            # print(f"Response header: {response_header}")

            # Compose multiple answers
            answers = []
            for question in questions:
                answer = Answer(
                    name = question.encode_name(),
                    type_ = question.type_,
                    class_ = question.class_,
                    ttl = 100,
                    data = socket.inet_aton('8.8.8.8')
                )
                answers.append(answer)
            # print(f"Constructed answers: {answers}")
            
            # Create response message
            response_msg = Message(
                header = response_header,
                questions = questions,
                answers = answers
            )
            # print(f"Response message: {response_msg}")
                        
            # Convert to bytes and send
            udp_socket.sendto(response_msg.to_bytes(), source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            print(f"Stack trace:", traceback.format_exc()) 
            break

if __name__ == "__main__":
    main()
