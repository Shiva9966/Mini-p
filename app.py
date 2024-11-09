from flask import Flask, request, render_template, redirect, url_for, session
import boto3
import os
import random
import smtplib
from email.mime.text import MIMEText
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Needed for session management

# Load environment variables from .env file
load_dotenv()

# AWS clients with region specification and SSL verification disabled
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
s3_client = boto3.client('s3', region_name=AWS_REGION, verify=False)
kms_client = boto3.client('kms', region_name=AWS_REGION, verify=False)

# Load environment variables for bucket name, KMS key ID, and SMTP configuration
BUCKET_NAME = os.getenv('BUCKET_NAME')
KMS_KEY_ID = os.getenv('KMS_KEY_ID')
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

def send_otp_via_email(email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg['Subject'] = 'Your One-Time Password'
    msg['From'] = SMTP_USERNAME
    msg['To'] = email

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()  # Secure the connection
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, email, msg.as_string())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    email = request.form['email']
    otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
    session['otp'] = otp  # Store OTP in the session
    send_otp_via_email(email, otp)
    return "OTP sent to your email."

@app.route('/upload_with_encryption', methods=['POST'])
def upload_with_encryption():
    file = request.files['file']
    file_content = file.read()

    # Generate a data encryption key (DEK)
    response = kms_client.generate_data_key(KeyId=KMS_KEY_ID, KeySpec='AES_256')
    plaintext_key = response['Plaintext']
    encrypted_key = response['CiphertextBlob']

    # Encrypt the file content using the DEK
    cipher = Cipher(algorithms.AES(plaintext_key), modes.CBC(b'0000000000000000'))
    encryptor = cipher.encryptor()

    # Padding for the file content
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_content) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Upload the encrypted file to S3
    s3_client.put_object(
        Bucket=BUCKET_NAME,
        Key=f"encrypted/{file.filename}",  # Store in "encrypted" folder
        Body=encrypted_data,
        Metadata={
            'x-amz-key': encrypted_key.hex(),
            'encryption-status': 'encrypted'
        }
    )

    return "File uploaded with encryption successfully."

@app.route('/upload_without_encryption', methods=['POST'])
def upload_without_encryption():
    file = request.files['file']
    file_content = file.read()

    # Upload the unencrypted file to S3
    s3_client.put_object(
        Bucket=BUCKET_NAME,
        Key=f"unencrypted/{file.filename}",  # Store in "unencrypted" folder
        Body=file_content,
        Metadata={'encryption-status': 'unencrypted'}
    )

    return "File uploaded without encryption successfully."

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    otp = request.form['otp']
    if otp != session.get('otp'):
        return "Invalid OTP. Please try again."

    file_name = request.form['filename']
    obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=f"encrypted/{file_name}")
    encrypted_file = obj['Body'].read()
    encrypted_key = bytes.fromhex(obj['Metadata']['x-amz-key'])

    # Decrypt the DEK using KMS
    response = kms_client.decrypt(CiphertextBlob=encrypted_key)
    plaintext_key = response['Plaintext']

    # Decrypt the file content using the DEK
    cipher = Cipher(algorithms.AES(plaintext_key), modes.CBC(b'0000000000000000'))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_file) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    # Save the decrypted file back to S3 and delete the encrypted file
    s3_client.put_object(
        Bucket=BUCKET_NAME,
        Key=f"decrypted/{file_name}",  # Store in "decrypted" folder
        Body=decrypted_data,
        Metadata={'encryption-status': 'decrypted'}
    )

    # Remove the encrypted file
    s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"encrypted/{file_name}")

    return "File decrypted and saved. The encrypted file has been removed."

@app.route('/delete_file', methods=['POST'])
def delete_file():
    file_name = request.form['filename']
    # Delete the file from S3
    s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"unencrypted/{file_name}")
    s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"encrypted/{file_name}")
    s3_client.delete_object(Bucket=BUCKET_NAME, Key=f"decrypted/{file_name}")
    return "File deleted successfully."

if __name__ == '__main__':
    app.run(debug=True)
