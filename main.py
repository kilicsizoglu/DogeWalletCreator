import hashlib
import os

import base58
import ecdsa


def generete_private_key():
    return os.urandom(32).hex()


def generete_public_key(private_key):
    private_key_bytes = bytes.fromhex(private_key)
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = '04' + key_bytes.hex()
    return key_hex


def public_to_address(public_key):
    public_key_bytes = bytes.fromhex(public_key)
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(public_key_bytes).digest())
    network_byte = b'\x1e' + ripemd160.digest()
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    address = base58.b58encode(network_byte + checksum)
    return address.decode('utf-8')


def main():
    private_key = generete_private_key()
    public_key = generete_public_key(private_key)
    address = public_to_address(public_key)
    print("Özel Anahtar:", private_key)
    print("Genel Anahtar:", public_key)
    print("Cüzdan Adresi:", address)


if __name__ == '__main__':
    main()
