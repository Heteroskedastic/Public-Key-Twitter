from functools import reduce
import unicodedata as ud
import elgamal
from twython import Twython



def alphabet():
    u = ''.join(chr(i) for i in range(65536) if (ud.category(chr(i)) in ('Lu', 'Ll')))[:1000]
    # ('Lu', 'Ll', 'Lt', 'Lm', 'Lo' )
    #u = ''.join(chr(i) for i in range(65536) if (ud.category(chr(i)) in ('Lu', 'Ll', 'Lt', 'Lm', 'Lo')))
    alphabet_size = len(u)
    decoderdict = dict((b, a) for a, b in enumerate(u))
    return u, alphabet_size, decoderdict


def key_compress(integer):
    (alpha, size, decode) = alphabet()
    a, b = divmod(integer, size)
    if a == 0:
        return alpha[b]
    return key_compress(a) + alpha[b]


def message_compress(cyphertext):
    (alpha, size, decode) = alphabet()
    t = ''
    for i in cyphertext.strip(' ').split(' '):
        #print('int is ' + i)
        a, b = divmod(int(i), size)
        #print('b is -'+str(b))
        #print('a is -'+str(a))
        if a == 0:
            t = t + alpha[b]
            t = t+'|'
            #print('t is-'+t, len(t))
        else:
            t = t + key_compress(a) + alpha[b]
            t = t+'|'
            #print('t is-'+t, len(t))
    return t


def key_expand(code):
    (alpha, size, decode) = alphabet()
    return int(reduce(lambda n, d: n*size + decode[d], code, 0))


def get_public_key(twitter, user):
    d = twitter.show_user(screen_name=user)['description']
    g, h, p, iNumBits = d.split('|TPK|')[1].split('|')
    e = elgamal.PublicKey(p=key_expand(p), g=key_expand(g), h=key_expand(h), iNumBits=key_expand(iNumBits))
    return e, key_expand(g), key_expand(h), key_expand(p)


def make_twitter_public(pkey):
    # g, h, p as defined h = g^x mod p in ElGamal
    # TPK is stands for Twitter Public Key
    return '|TPK|' + '|'.join(key_compress(n) for n in pkey)


def make_key_pair(iNumBits=256, iConfidence=32):
    # make a private/public key pair
    # TODO add p and t options for generate key
    e = elgamal.generate_keys()
    ekeys = dict()
    ekeys['PublicKey'] = make_twitter_public((e['publicKey'].p, e['publicKey'].g,
                                              e['publicKey'].h, e['publicKey'].iNumBits))
    ekeys['PrivateKey'] = (e['privateKey'].p, e['privateKey'].g, e['privateKey'].x,
                           e['privateKey'].iNumBits)
    return ekeys




