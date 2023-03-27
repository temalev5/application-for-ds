import base64
import os
import smtplib as smtp
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import PSS

from dotenv import load_dotenv
load_dotenv('../.env')


# Отправка письма с прикрепленным файлом
def send_email(_sender_email, _sender_password, _receiver_email, _subject, _attachment_path, _signature):
    message = MIMEMultipart()
    message["From"] = _sender_email
    message["To"] = _receiver_email
    message["Subject"] = _subject

    message.attach(MIMEText(_signature.decode("utf-8"), "plain"))

    with open(_attachment_path, "rb") as attachment:
        part = MIMEApplication(
            attachment.read(),
            Name=os.path.basename(_attachment_path)
        )
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(_attachment_path)}"'
        message.attach(part)

    with smtp.SMTP_SSL('smtp.yandex.com') as server:
        server.set_debuglevel(1)
        server.ehlo(_sender_email)
        server.login(_sender_email, _sender_password)
        server.auth_plain()
        server.sendmail(_sender_email, _receiver_email, message.as_string())
        print("Письмо успешно отправлено!")
        server.quit()


# Получение модели приватного ключа из файла
def get_private_key(key_path):
    with open(key_path, "rb") as key_file:
        _private_key_modal = serialization.load_pem_private_key(key_file.read(), password=None)
        return _private_key_modal


# Создание подписи файла
def sign_file(key_path, file_path, _signature_file_path):
    _private_key_modal = get_private_key(key_path)

    with open(file_path, "rb") as file:
        file_data = file.read()

    _signature = _private_key_modal.sign(
        data=file_data,
        padding=padding.PSS(padding.MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        algorithm=hashes.SHA256()
    )

    _signature = base64.b64encode(_signature)

    with open(_signature_file_path, "wb") as f:
        f.write(_signature)

    return _signature


# Генерация публичного ключа на основе модели приватного ключа с сохранением в файл
def generate_public_key(_private_key_modal, _public_key_path):
    _public_key_modal = _private_key_modal.public_key()
    with open(_public_key_path, "wb") as f:
        f.write(_public_key_modal.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return _public_key_modal


# Генерация приватного ключа с сохранением в файл
def generate_private_key(_private_key_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(_private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return private_key


# Генерация пары ключей приватного и публичного
def generate_keypair(_private_key_path, _public_key_path):
    _private_key_modal = generate_private_key(_private_key_path)
    _public_key_modal = generate_public_key(_private_key_modal, _public_key_path)

    return _private_key_modal, _public_key_modal


if __name__ == '__main__':
    private_key_path = os.getenv("private_key_path")
    public_key_path = os.getenv("public_key_path")
    letter_file_path = os.getenv("letter_file_path")
    signature_file_path = os.getenv("signature_file_path")

    sender_email = os.getenv("sender_email")
    sender_password = os.getenv("sender_password")
    receiver_email = os.getenv("receiver_email")
    subject = os.getenv("subject")

    private_key_modal, public_key_modal = generate_keypair(private_key_path, public_key_path)

    signature = sign_file(private_key_path, letter_file_path, signature_file_path)
    send_email(sender_email,
               sender_password,
               receiver_email,
               subject,
               letter_file_path,
               signature)
