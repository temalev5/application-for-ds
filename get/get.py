import base64
import email
from email.header import decode_header
from imaplib import IMAP4_SSL
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import PSS


# Получение модели публичного ключа из файла
def get_public_key(key_path):
    with open(key_path, "rb") as key_file:
        public_key_modal = serialization.load_pem_public_key(key_file.read())
        return public_key_modal


# Получение текста и файла из письма
def get_email_text_and_file(_imap_server, _imap_username, _imap_password, _public_key_path):
    imap = IMAP4_SSL(_imap_server, 993)
    imap.login(_imap_username, _imap_password)

    imap.select('INBOX')

    # Поиск писем
    typ, msg_ids = imap.search(None, 'ALL')

    # Получение последнего письма
    last_msg_id = msg_ids[0].split()[-1]
    typ, msg_data = imap.fetch(last_msg_id, '(RFC822)')

    msg = email.message_from_bytes(msg_data[0][1])
    subject = decode_header(msg["Subject"])[0][0]
    sender = decode_header(msg["From"])[0][0]
    receiver = decode_header(msg["To"])[0][0]
    print(f"Subject: {subject}")
    print(f"From: {sender}")
    print(f"To: {receiver}")

    msg_text = b''
    data = b''
    for part in msg.walk():
        # игнорируем все, кроме текстовых и прикрепленных файлов
        if part.get_content_type() == "text/plain":
            body = part.get_payload(decode=True)
            msg_text = body
        elif part.get_content_type() == "application/octet-stream":
            filename = decode_header(part.get_filename())[0][0]
            data = part.get_payload(decode=True)
            with open(filename, "wb") as f:
                f.write(data)
            print(f"File '{filename}' successfully saved!")

    msg_text = base64.b64decode(msg_text)
    imap.close()
    imap.logout()

    return msg_text, data


# Проверка подписи
def verify_signature(_signature, _file_data, _public_key_path):
    public_key_modal = get_public_key(_public_key_path)

    try:
        public_key_modal.verify(
            _signature,
            _file_data,
            padding=padding.PSS(padding.MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
            algorithm=hashes.SHA256()
        )
        print("Проверка подписи прошла успешно!")
        return True
    except InvalidSignature:
        print("Некорректная подпись")
        return False


if __name__ == '__main__':
    imap_server = "imap.yandex.com"
    imap_username = "antkonst016@yandex.ru"
    imap_password = ""
    public_key_path = "../public_key.pem"

    signature, file_data = get_email_text_and_file(
        imap_server,
        imap_username,
        imap_password,
        public_key_path)

    verify_signature(signature,
                     file_data,
                     public_key_path)
