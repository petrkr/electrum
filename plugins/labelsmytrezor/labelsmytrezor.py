import hashlib
import json
import os

from trezorlib.client import TrezorClient
from trezorlib.transport_hid import HidTransport
from binascii import hexlify, unhexlify
import hmac, base58
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import base64

import electrum
from electrum.plugins import BasePlugin, hook
from electrum.i18n import _


class LabelsMyTrezorPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

        # Regarding to SLIP-0015 encode/decode constant
        self.constant = unhexlify("0123456789abcdeffedcba9876543210")
        self.account_key = None

    def get_masterkey(self):
        client = TrezorClient(HidTransport(HidTransport.enumerate()[0]))
        bip32_path = client.expand_path("10015'/0'")
        masterkey = client.encrypt_keyvalue(
            bip32_path,
            "Enable labeling?",
            unhexlify("fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef"),
            True,
            True
        )
        return hexlify(masterkey)

    def get_accountkey(self, xpub, masterkey_hex):
        key = hmac.new(unhexlify(masterkey_hex), xpub, hashlib.sha256).digest()
        key = base58.b58encode_check(key)
        print key
        return key

    def encode(self, account_key, data):
        print "encode"
        print account_key
        digest = hmac.new(account_key, self.constant, hashlib.sha512).digest()
        filename = hexlify(digest[0:32]) + ".mtdt"
        print filename

        backend = default_backend()
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(digest[32:64]), modes.GCM(iv), backend=backend)
        encryptor = cipher.encryptor()
        ctext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        output = iv+tag+ctext

        output_hex = base64.b64encode(output)
        print output_hex
        return output_hex

    def decode(self, account_key, cdata):
        print account_key
        digest = hmac.new(account_key, self.constant, hashlib.sha512).digest()
        filename = hexlify(digest[0:32]) + ".mtdt"
        print filename

        iv = cdata[0:12]
        tag = cdata[12:28]

        backend = default_backend()
        cipher = Cipher(algorithms.AES(digest[32:64]), modes.GCM(iv, tag), backend=backend)
        decryptor = cipher.decryptor()
        cdata_start = 12 + 16
        cdata_bsize = 16
        cdata_position = 0
        data = ""
        while ((cdata_position * cdata_bsize) + cdata_start) < len(cdata)-1:
            block = cdata[cdata_start + (cdata_position * cdata_bsize)
                          :
                          cdata_start + (cdata_position * cdata_bsize) + cdata_bsize]
            data = data + decryptor.update(block)
            cdata_position += 1

        print data
        return data

    def generate_slip0015_labels(self, wallet):
        print "generate_slip0015_labels start"
        slipoutput = dict()
        slipoutput['version'] = "1.0.0"
        slipoutput['outputLabels'] = dict()
        slipoutput['accountLabel'] = "Main"
        slipoutput['addressLabels'] = dict()

        for (txid, label) in wallet.labels.iteritems():
            if txid not in wallet.txi and txid not in wallet.txo:
                continue

            if len(wallet.txi[txid]) == 0:
                # Incoming transaction
                for addr, val in wallet.txo[txid].iteritems():
                    if txid not in slipoutput['outputLabels']:
                        slipoutput['outputLabels'][txid] = dict()

                    slipoutput['outputLabels'][txid][str(val[0][0])] = label
            else:
                # Index of first not own address
                txindex = 0

                # Outgoing transaction, find first not mine address
                for addr, val in wallet.txo[txid].iteritems():
                    if txindex is not val[0][0]:
                        break
                    txindex += 1

                if txid not in slipoutput['outputLabels']:
                    slipoutput['outputLabels'][txid] = dict()

                slipoutput['outputLabels'][txid][str(txindex)] = label

        print slipoutput
        print self.encode(self.account_key, json.dumps(slipoutput))

        print "generate_slip0015_labels end"

    def get_wallet_key(self, wallet):
        key = wallet.storage.get('mytrezor_wallet_key')
        if key is None:
            key = self.get_accountkey(wallet.get_fingerprint(), self.get_masterkey())
            self.set_wallet_key(wallet, key)
        return key.encode('utf-8')

    def set_wallet_key(self, wallet, key):
        self.print_error("set", wallet.basename(), "account key to", key)
        wallet.storage.put("mytrezor_wallet_key", key)

    @hook
    def set_label(self, wallet, item, label):
        print "Set label: "
        print "Item"
        print item
        print "Label"
        print label

    def start_wallet(self, wallet):
        self.account_key = self.get_wallet_key(wallet)
        self.print_error("wallet", wallet.basename(), "account key is", self.account_key)

    def stop_wallet(self, wallet):
        pass
