import hashlib
import ecdsa
import base58


def private_key_to_public_key(private_key_hex):
    # 将私钥从16进制字符串转化为字节
    private_key_bytes = bytes.fromhex(private_key_hex)

    # 使用secp256k1曲线生成签名密钥对象
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)

    # 获取公钥，生成压缩公钥
    public_key = sk.get_verifying_key().to_string("compressed")

    return public_key


def public_key_to_address(public_key):
    # 第一步：SHA-256哈希公钥
    sha256_hash = hashlib.sha256(public_key).digest()

    # 第二步：RIPEMD-160哈希
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

    # 第三步：版本前缀（0x00用于P2PKH地址）
    versioned_payload = b'\x00' + ripemd160_hash

    # 第四步：计算校验和
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]

    # 最终地址：版本前缀 + 公钥哈希 + 校验和
    address_bytes = versioned_payload + checksum

    # 使用Base58Check编码
    address = base58.b58encode(address_bytes).decode('utf-8')

    return address


def generate_btc_addresses(start_hex, end_hex):
    # 转换起始和结束私钥为整数
    start_int = int(start_hex, 16)
    end_int = int(end_hex, 16)

    # 遍历私钥范围
    for private_key_int in range(start_int, end_int + 1):
        # 将整数转为16进制字符串
        private_key_hex = hex(private_key_int)[2:].zfill(64)  # 保证私钥为64字符长度

        # 获取公钥和比特币地址
        public_key = private_key_to_public_key(private_key_hex)
        btc_address = public_key_to_address(public_key)

        # 打印私钥和对应的比特币地址
        print(f"Private Key: {private_key_hex}")
        print(f"BTC Address: {btc_address}\n")
        if btc_address == '1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9':
            print('!!!!!!!!!!!!!!!!!!', private_key_hex)
            exit(1)


# 设置私钥范围
start_private_key = "4000000000000000000000000000000000000000000000000000000009305179"
end_private_key = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

# 生成BTC地址
generate_btc_addresses(start_private_key, end_private_key)
