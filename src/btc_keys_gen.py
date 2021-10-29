# btc_keys_gen
import ecdsa
import binascii
import hashlib
from base58 import b58encode
import os
import sys
import base58
import codecs



def get_private_key_wif(priv_key_byte, compressed):
    """Apenas para demonstração e estudo"""

    # Add prefixo da mainet
    priv_k = b'\x80' + priv_key_byte

    # Add compressed flag
    if compressed:
        priv_k += b'\x01'

    # Checksum - 4 bytes
    checksum = hashlib.sha256(hashlib.sha256(priv_k).digest()).digest()[:4]
    priv_k = priv_k + checksum

    # Private wif
    private_address = str(b58encode(priv_k), 'utf-8')

    return private_address

def get_public_key_wif(priv_key_byte, compressed):
    """Apenas para demonstração e estudo"""

    # Cálculo da chave publica pela Curva Elíptica - SECP256k1
    signing_key = ecdsa.SigningKey.from_string(priv_key_byte, curve=ecdsa.SECP256k1)
    verifying_key = (signing_key.get_verifying_key()).to_string()

    # Forma Compressed
    if compressed:
        public_key_hex_y = verifying_key.hex()[67:]
        if (int(public_key_hex_y, 16) % 2) == 0:
            pub_key = bytes.fromhex("02") + verifying_key  # compressed ( numeros pares )
        else:
            pub_key = bytes.fromhex("03") + verifying_key  # compressed ( numeros ímpares )
        pubkey_hex = pub_key.hex()[:66]

    # Forma Uncompressed
    else:
        pub_key = bytes.fromhex("04") + verifying_key  # uncompressed
        pubkey_hex = pub_key.hex()  # uncompressed

    # Conversão para Byte
    pubkey_bytes = codecs.decode(pubkey_hex.encode('utf-8'), 'hex')
    # Hash256
    pubkey_sha256 = hashlib.sha256(pubkey_bytes)
    # Hash riemp160
    pubkey_ripe = hashlib.new('ripemd160')
    # Hash256
    pubkey_ripe.update(pubkey_sha256.digest())

    raw_address = '00' + pubkey_ripe.hexdigest()

    # BTC hash160
    #hash160 = pubkey_ripe.hexdigest()

    # Public wif
    raw_addr_bytes = codecs.decode(raw_address.encode('utf-8'), 'hex')
    addr_shasha = hashlib.sha256(hashlib.sha256(raw_addr_bytes).digest())
    checksum = addr_shasha.hexdigest()[:8]
    address = raw_address + checksum
    addr_bytes = codecs.decode(address.encode('utf-8'), 'hex')
    public_address = str(b58encode(addr_bytes), 'utf-8')

    return public_address



priv_key_byte = os.urandom(32)
priv_key_hex = binascii.hexlify(priv_key_byte).decode()

print("\nPrivate key:")
print(priv_key_hex)
print(get_private_key_wif(priv_key_byte, compressed=True))
print("\nPublic key:")
print(get_public_key_wif(priv_key_byte, compressed=True))


