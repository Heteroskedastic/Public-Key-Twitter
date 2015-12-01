import configparser
import random
from key_tools import key_compress, key_expand, get_public_key
from messaging import send_status_update


#todo, setup tests


config = configparser.ConfigParser()
config.read('user_data.ini')
consumer_key = config['HeteroT1']['consumer_key']
consumer_sec = config['HeteroT1']['consumer_sec']
access_tok = config['HeteroT1']['access_tok']
access_token_sec = config['HeteroT1']['access_token_sec']

def public_key_coding():
    n = random.getrandbits(300)
    short = key_compress(n)
    backagain = key_expand(short)
    nlen = len(str(n))
    print (nlen, len(short), float(len(short))/nlen)
    assert n == backagain, (n,short)

#send_status_update(consumer_key, consumer_sec, access_tok, access_token_sec)

public_key_coding()

k = get_public_key(consumer_key, consumer_sec, access_tok, access_token_sec, 'heterot1')
print(k)

