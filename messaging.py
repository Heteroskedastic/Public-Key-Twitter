import elgamal
from twython import Twython, TwythonError
from datetime import datetime as d

def encrypt_message(plaintext, reciever, publicKey=None):
    # encrypt the message
    if publicKey != None:
        return elgamal.encrypt(publicKey, plaintext)
    else:
        return elgamal.encrypt(get_receiver_key(user_id), plaintext)

def decrypt_message(cyphertext, privateKey):
    # try to decrypt message
    return elgamal.decrypt(privateKey, cyphertext)


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


def send_status_update(consumer_key, consumer_sec, access_tok, access_token_sec,
                       message="test " + str(d.now())):
    twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
    twitter.update_status(status=message)
    print("message sent ")
    print("message - ", message)

#send_user_messages()

#x = get_user_description(consumer_key, consumer_sec, access_tok, access_token_sec, 'heterot2')