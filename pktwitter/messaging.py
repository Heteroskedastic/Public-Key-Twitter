import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime as d
from urllib import request
from twython import Twython

from pktwitter.elgamal2 import encrypt, decrypt
from pktwitter.key_tools import key_compress, key_expand


class BaseMessage:
    def get_user_pub_key(self, username):
        try:
            # url = "https://publickeykeeper.org/api/get-key"
            url = "http://127.0.0.1:5000/api/get-key"
            params = json.dumps({'service': 'twitter', 'account': username}).encode('utf-8')
            headers = {}
            headers['Content-Type'] = 'application/json'
            req = request.Request(url, params, headers, method="GET")
            data = json.loads(request.urlopen(req).read().decode('utf8', 'ignore'))
        except:
            raise ValueError("Can't get a public key")
        key = base64.b64decode(data["key"])
        return serialization.load_der_public_key(key, default_backend())


class TwitterMessage(BaseMessage):

    def __init__(self, consumer_key, consumer_sec, access_tok, access_token_sec, username):
        self.twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
        self.public_key = self.get_user_pub_key(username)

    def encrypt_message(self, plaintext):
        cypher_compressed = self.public_key.encrypt(
            plaintext,
            padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
            )
        )
        cypher_compressed = ''.join(key_compress(int(n)) for n in cypher_compressed)
        return cypher_compressed

    def decrypt_message(self, privatekey, cypher_compressed):
        # try to decrypt message
        cypher_int = ' '.join(str(key_expand(c)) for c in cypher_compressed.split('|')) + ' '
        return decrypt(privatekey, cypher_int)

    def get_user_messages(self, consumer_key, consumer_sec, access_tok, access_token_sec, username='heteroT1'):
        # user_timeline = twitter.get_user_timeline(screen_name='HeteroT1')
        user_messages = self.twitter.get_direct_messages(screen_name=username)
        for message in user_messages:
            print("message - ", message)

    def send_direct_messages(self, username, message):
        msg = self.encrypt_message(str.encode(message))
        message = self.twitter.send_direct_message(screen_name=username, text=msg)
        print("message sent ")

    def send_status_update(self, message="test " + str(d.now())):
        # twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
        self.twitter.update_status(status=message)
        print("message sent ")
        print("message - ", message)

