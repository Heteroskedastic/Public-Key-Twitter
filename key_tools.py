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


def key_expand(code):
    (alpha, size, decode) = alphabet()
    return int(reduce(lambda n, d: n*size + decode[d], code, 0))

def assemblePublicKeyElgamal(tpk):
    # PublicKey(p, g, h, iNumBits)
    p, g, h, iNumBits = tpk.split('|TPK|')[1].split('|')
    e = elgamal.PublicKey(key_expand(p), key_expand(g), key_expand(h), key_expand(iNumBits))
    return e

def assemblePrivateKeyElgamal(ints):
    # ints is a tuple if (p, g, x, iNumBits)
    return elgamal.PrivateKey(ints[0], ints[1], ints[2], ints[3])


def get_public_key(twitter, user):
    d = twitter.show_user(screen_name=user)['description']
    assert '|TPK|' in d, "Did not find a Twitter public key |tpk|"
    return d

def make_twitter_public(pkey):
    # publicKey = PublicKey(p, g, h, iNumBits)
    # p, g, h as defined h = g^x mod p in ElGamal
    # TPK is stands for Twitter Public Key
    return '|TPK|' + '|'.join(key_compress(n) for n in (pkey.p, pkey.g, pkey.h, pkey.iNumBits))


def make_key_pair(iNumBits=256, iConfidence=32):
    # make a private/public key pair
    # TODO add p and t options for generate key
    e = elgamal.generate_keys()
    ekeys = dict()
    ekeys['PublicKey'] = make_twitter_public(e['publicKey'])
    ekeys['PrivateKey'] = (e['privateKey'].p, e['privateKey'].g, e['privateKey'].x,
                           e['privateKey'].iNumBits)
    return ekeys




