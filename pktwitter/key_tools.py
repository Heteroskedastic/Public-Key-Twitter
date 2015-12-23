from unicodedata import ucd_3_2_0 as ud
from functools import reduce

from pktwitter.elgamal2 import PrivateKey, generate_keys, PublicKey


def alphabet():
    u = ''.join(chr(i) for i in range(65536) if (ud.category(chr(i)) in ('Lu', 'Ll')))[:1000]
    # ('Lu', 'Ll', 'Lt', 'Lm', 'Lo' )
    # u = ''.join(chr(i) for i in range(65536) if (ud.category(chr(i)) in ('Lu', 'Ll', 'Lt', 'Lm', 'Lo')))
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


def assemble_publickey(tpk):
    # PublicKey(p, g, h, iNumBits)
    p, g, h, iNumBits = tpk.split('|TPK|')[1].split('|')
    e = PublicKey(key_expand(p), key_expand(g), key_expand(h), key_expand(iNumBits))
    return e


def assemble_privatekey(ints):
    # ints is a tuple if (p, g, x, iNumBits)
    return PrivateKey(ints[0], ints[1], ints[2], ints[3])


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
    e = generate_keys()
    ekeys = dict()
    ekeys['TwitterKey'] = make_twitter_public(e['publicKey'])
    ekeys['PrivateKey'] = {'p': e['privateKey'].p, 'g': e['privateKey'].g, 'x': e['privateKey'].x, 'iNumBits': e['privateKey'].iNumBits}
    ekeys['PublicKey'] = {'p': e['publicKey'].p, 'g': e['publicKey'].g, 'h': e['publicKey'].h, 'iNumBits': e['publicKey'].iNumBits}
    return ekeys

