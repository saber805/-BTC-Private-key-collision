import os
import struct
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import shutil

# 常量
BLOCK_SIZE = 16  # AES的块大小

def generate_key(password: str, salt: bytes) -> bytes:
    """生成256位的AES密钥"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str, output_dir: str):
    """加密单个文件"""
    # 生成盐和IV
    salt = os.urandom(16)
    iv = os.urandom(16)

    # 读取文件内容
    with open(file_path, 'rb') as file:
        file_data = file.read()

    # 填充文件内容
    padding_length = BLOCK_SIZE - len(file_data) % BLOCK_SIZE
    padded_data = file_data + bytes([padding_length]) * padding_length

    # 生成密钥
    key = generate_key(password, salt)

    # 创建加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 加密数据
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # 创建加密后的文件
    encrypted_file_path = os.path.join(output_dir, os.path.basename(file_path) + '.enc')
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(salt + iv + encrypted_data)
    print(f"Encrypted {file_path} -> {encrypted_file_path}")

def decrypt_file(encrypted_file_path: str, password: str, output_dir: str):
    """解密单个文件"""
    # 读取加密文件内容
    with open(encrypted_file_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()

    # 提取盐和IV
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    data = encrypted_data[32:]

    # 生成密钥
    key = generate_key(password, salt)

    # 创建解密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # 解密数据
    decrypted_data = decryptor.update(data) + decryptor.finalize()

    # 移除填充
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]

    # 保存解密后的文件
    decrypted_file_path = os.path.join(output_dir, os.path.basename(encrypted_file_path)[:-4])  # 去掉 `.enc` 后缀
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    print(f"Decrypted {encrypted_file_path} -> {decrypted_file_path}")

def encrypt_folder(folder_path: str, password: str, output_dir: str):
    """加密文件夹"""
    # 如果输出目录不存在，则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 遍历文件夹中的所有文件和子文件夹
    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            encrypt_file(file_path, password, output_dir)

def decrypt_folder(encrypted_folder_path: str, password: str, output_dir: str):
    """解密文件夹"""
    # 如果输出目录不存在，则创建
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 遍历加密文件夹中的所有文件
    for root, dirs, files in os.walk(encrypted_folder_path):
        for file_name in files:
            encrypted_file_path = os.path.join(root, file_name)
            if encrypted_file_path.endswith('.enc'):  # 只解密 `.enc` 文件
                decrypt_file(encrypted_file_path, password, output_dir)


if __name__ == "__main__":
    # 示例密码和文件夹路径
    password = "passward"
    folder_path = "H:\BIANCES\私钥碰撞\入库代码"  # 替换为你的文件夹路径
    encrypted_folder_path = "H:\BIANCES\私钥碰撞\加密内容"
    decrypted_folder_path = "H:\BIANCES\私钥碰撞\解密内容"

    # # 加密文件夹
    # print(f"Encrypting folder {folder_path}...")
    # encrypt_folder(folder_path, password, encrypted_folder_path)

    # 解密文件夹
    print(f"\nDecrypting folder {encrypted_folder_path}...")
    decrypt_folder(encrypted_folder_path, password, decrypted_folder_path)
