import struct
import base64
import hmac
import hashlib
import random

import pyelliptic
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def _repad(data):
  """Add base64 padding to the end of a string, if required"""
  ret = data + b"===="[:len(data) % 4]
  ret = ret.encode('utf-8')
  return ret


def hkdf(salt, ikm, info, length):
  if length > 32:
    raise "Cannot return keys of more than 32 bytes"

  # extract
  key = hmac.new(salt, msg=ikm, digestmod=hashlib.sha256).digest()

  # expand
  infoHmac = hmac.new(key, msg=info, digestmod=hashlib.sha256)
  infoHmac.update(chr(1))
  return infoHmac.digest()[0:length]


def create_info(info_type, receiver_pubkey, sender_pubkey):
  text = bytes((
      'Content-Encoding: %s'
      '\0'
      'P-256'
      '\0'
  ) % info_type)

  # a list of (data_contenxt, format)
  data_fmt_pairs = [
      # text
      (text, '%ds' % len(text)),

      # receiver_pubkey (short int) length in big-endian,
      # > means big-endian, and it has to be placed at the beginning
      # That is why we
      (struct.pack('>h', len(receiver_pubkey)), '2s'),
      # receiver_pubkey
      (receiver_pubkey, '%ds' % len(receiver_pubkey)),

      # sender_pubkey (short int) length in big-endian
      (struct.pack('>h', len(sender_pubkey)), '2s'),
      # sender_pubkey
      (sender_pubkey, '%ds' % len(sender_pubkey)),
  ]

  args = []
  fmt_spec = ''

  for data, fmt in data_fmt_pairs:
    args.append(data)
    fmt_spec += fmt

  return struct.pack(fmt_spec, *args)


def iv(base, counter):
    if (counter >> 64) != 0:
        raise Exception(u"Counter too big")
    (mask,) = struct.unpack("!Q", base[4:])
    return base[:4] + struct.pack("!Q", counter ^ mask)


class PushEncryptor(object):

  def __init__(
        self, subscription, sender_pubkey_str=None, sender_privkey_str=None,
        curve='prime256v1'):
    self.curve = curve
    self.subscription = subscription
    self.receiver_pubkey = base64.urlsafe_b64decode(
        _repad(self.subscription['keys']['p256dh']))
    self.receiver_authsecret = base64.urlsafe_b64decode(
        _repad(self.subscription['keys']['auth'])
    )

    if sender_privkey_str:
      self.sender_privkey = base64.urlsafe_b64decode(_repad(sender_privkey_str))
      self.sender_pubkey = base64.urlsafe_b64decode(_repad(sender_pubkey_str))
      self.sender_ecc = pyelliptic.ECC(
          pubkey=self.sender_pubkey,
          privkey=self.sender_privkey, curve=self.curve)
    else:
      self.sender_ecc = pyelliptic.ECC(curve=self.curve)
      self.sender_privkey = self.sender_ecc.get_privkey()

    self.ecdh_key = self.sender_ecc.get_ecdh_key(self.receiver_pubkey)

  def crypto_info(self, salt=None):
    if salt:
      salt = base64.urlsafe_b64decode(_repad(salt))
    else:
      salt = bytearray(random.getrandbits(8) for _ in range(16))

    auth_info = 'Content-Encoding: auth\0'.encode('utf-8')

    prk = hkdf(self.receiver_authsecret, self.ecdh_key, auth_info, 32)
    CEK_info = create_info('aesgcm', self.receiver_pubkey, self.sender_pubkey)
    CEK = hkdf(salt, prk, CEK_info, 16)

    nonce_info = create_info('nonce', self.receiver_pubkey, self.sender_pubkey)
    nonce = hkdf(salt, prk, nonce_info, 12)
    return {
        'ikm': self.ecdh_key,
        'prk': prk,
        'CEK_info': CEK_info,
        'CEK': CEK,
        'nonce_info': nonce_info,
        'nonce': nonce,
    }

  def encrypt(self, crypto_info, text):
    key = algorithms.AES(crypto_info['CEK'])
    mode = modes.GCM(crypto_info['nonce'])
    encryptor = Cipher(key, mode, backend=default_backend()).encryptor()
    data = encryptor.update(
        b"\0\0" + text.encode('utf-8')) + encryptor.finalize()
    data += encryptor.tag
    return data
