from datetime import datetime as d

from twython import Twython

from pktwitter.elgamal2 import encrypt, decrypt
from pktwitter.key_tools import key_compress, key_expand


def encrypt_message(plaintext, publickey):
    # encrypt the message
    # privateKey is a elgamal object
    # return elgamal.encrypt(publicKey, plaintext)
    cypher_int = encrypt(publickey, plaintext)
    cypher_compressed = '|'.join(key_compress(int(n)) for n in cypher_int.strip(' ').split(' '))
    return cypher_compressed


def decrypt_message(privatekey, cypher_compressed):
    # try to decrypt message
    cypher_int = ' '.join(str(key_expand(c)) for c in cypher_compressed.split('|')) + ' '
    return decrypt(privatekey, cypher_int)


def get_user_messages(consumer_key, consumer_sec, access_tok, access_token_sec, username='heteroT1'):
    twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
    # user_timeline = twitter.get_user_timeline(screen_name='HeteroT1')
    user_messages = twitter.get_direct_messages(screen_name=username)
    for message in user_messages:
        print("message - ", message)


def send_direct_messages(consumer_key, consumer_sec, access_tok, access_token_sec, username='heteroT1',
                         message="test " + str(d.now())):

    twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
    message = twitter.send_direct_message(screen_name=username, text=message)
    print("message sent ")
    print("message - ", message)


def send_status_update(twitter, message="test " + str(d.now())):
    # witter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
    twitter.update_status(status=message)
    print("message sent ")
    print("message - ", message)

# send_user_messages()

# x = get_user_description(consumer_key, consumer_sec, access_tok, access_token_sec, 'heterot2')
