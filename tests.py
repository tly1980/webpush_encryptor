#!/usr/bin/env python
import json
import base64
import unittest


import push_encrypt


fixture_subscription = '''
{
    "endpoint": "https://android.googleapis.com/gcm/send/f1LsxkKphfQ:APA91bFUx7ja4BK4JVrNgVjpg1cs9lGSGI6IMNL4mQ3Xe6mDGxvt_C_gItKYJI9CAx5i_Ss6cmDxdWZoLyhS2RJhkcv7LeE6hkiOsK6oBzbyifvKCdUYU7ADIRBiYNxIVpLIYeZ8kq_A",
    "keys": {
        "p256dh": "BOLcHOg4ajSHR6BjbSBeX_6aXjMu1V5RrUYXqyV_FqtQSd8RzdU1gkMv1DlRPDIUtFK6Nd16Jql0eSzyZh4V2uc",
        "auth": "r9kcFt8-4Q6MnMjJHqJoSQ"
    }
}
'''


def B64(v):
    v1 = base64.urlsafe_b64encode(v)
    v2 = v1.strip('=')
    return v2


class PushEncryptTest(unittest.TestCase):

  def test_1(self):
    expected = {
        'ikm': 'sqTU9FqHSsn33eOUphilgrozqJFb7BCdYPjI2m78QM0',
        'prk': 'wV0sNSvW4PviyYKiaVTtPANmaSF7US5g3A5yj4bZeYw',
        'sender_pubkey': 'BG3OGHrl3YJ5PHpl0GSqtAAlUPnx1LvwQvFMIc68vhJU6nIkRzPEqtCduQz8wQj0r71NVPzr7ZRk2f-fhsQ5pK8',
        'receiver_pubkey': 'BOLcHOg4ajSHR6BjbSBeX_6aXjMu1V5RrUYXqyV_FqtQSd8RzdU1gkMv1DlRPDIUtFK6Nd16Jql0eSzyZh4V2uc',
        'CEK_info': 'Q29udGVudC1FbmNvZGluZzogYWVzZ2NtAFAtMjU2AABBBOLcHOg4ajSHR6BjbSBeX_6aXjMu1V5RrUYXqyV_FqtQSd8RzdU1gkMv1DlRPDIUtFK6Nd16Jql0eSzyZh4V2ucAQQRtzhh65d2CeTx6ZdBkqrQAJVD58dS78ELxTCHOvL4SVOpyJEczxKrQnbkM_MEI9K-9TVT86-2UZNn_n4bEOaSv',
        'CEK': '2V6MO66BhBHp0rOUDacExQ',
        'nonce_info': 'Q29udGVudC1FbmNvZGluZzogbm9uY2UAUC0yNTYAAEEE4twc6DhqNIdHoGNtIF5f_ppeMy7VXlGtRherJX8Wq1BJ3xHN1TWCQy_UOVE8MhS0Uro13XomqXR5LPJmHhXa5wBBBG3OGHrl3YJ5PHpl0GSqtAAlUPnx1LvwQvFMIc68vhJU6nIkRzPEqtCduQz8wQj0r71NVPzr7ZRk2f-fhsQ5pK8',
        'nonce': 'K7S4YO8AF3GM_ZwN',
        'cipher_text': 'IiQImHDLp7FUqR_b4sDybejMaLBUH6cXnZFlUrFlUg'
    }

    subscription = json.loads(fixture_subscription)
    args = {
        'sender_pubkey_str': 'BG3OGHrl3YJ5PHpl0GSqtAAlUPnx1LvwQvFMIc68vhJU6nIkRzPEqtCduQz8wQj0r71NVPzr7ZRk2f-fhsQ5pK8',
        'sender_privkey_str': 'Dt1CLgQlkiaA-tmCkATyKZeoF1-Gtw1-gdEP6pOCqj4',
    }

    pe = push_encrypt.PushEncryptor(
        subscription,
        **args)
    # check that s.split fails when the separator is not a string
    crypto_info_orig = pe.crypto_info(salt='4CQCKEyyOT_LysC17rsMXQ')
    crypto_info = dict([
        (k, B64(v))
        for k, v in crypto_info_orig.items()])

    self.assertEqual(expected['ikm'], crypto_info['ikm'])

    self.assertEqual(expected['prk'], crypto_info['prk'])

    # self.assertEqual(
    #     EXPECTED['sender_pubkey'],
    #     crypto_info['sender_pubkey'])

    # self.assertEqual(
    #     EXPECTED['receiver_pubkey'],
    #     crypto_info['receiver_pubkey'])

    self.assertEqual(expected['CEK_info'], crypto_info['CEK_info'])
    self.assertEqual(expected['CEK'], crypto_info['CEK'])
    self.assertEqual(expected['nonce_info'], crypto_info['nonce_info'])
    self.assertEqual(expected['nonce'], crypto_info['nonce'])
    #print crypto_info['CEK']

    plain_text = 'Hello, world!'
    cipher_text = pe.encrypt(crypto_info_orig, plain_text)
    self.assertEqual(expected['cipher_text'], B64(cipher_text))


if __name__ == '__main__':
    unittest.main()
