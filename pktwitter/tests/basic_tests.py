import configparser
import random
import string
from datetime import datetime as d
from unittest import TestCase

from pktwitter.messaging import encrypt_message, decrypt_message, send_status_update
from twython import Twython

from pktwitter.elgamal2 import PublicKey, encrypt, decrypt, generate_keys
from pktwitter.key_tools import key_compress, key_expand, get_public_key, assemble_publickey, assemble_privatekey, make_twitter_public

# Bob
h1_keys = {'PrivateKey': {'g': 24751437537389890194590657497357491645325854825567374144321182616248470389391,
                          'p': 86171467944154384762405147922450425872423195171219400197372357783518331285503,
                          'x': 85938432118568785220846806342156822575124367753119914968056518633737657379708,
                          'iNumBits': 256},
           'PublicKeyTwitter' : '|TPK|àĶʄքĥȔҚȪĞծɳɚԲɘŎĶŦȥŐȈǹүΒǞƨʨ|YҏɦΦșՄōϜЩʢǹʜНǘӹӚτȊěǔŁЀƃʇșț|DɺѝļΛǏΏǳίӬʎödȥӊΰŖęӀǖӜŊѥԿEϰ|Ƌ',
           'PublicKey': {'g': 24751437537389890194590657497357491645325854825567374144321182616248470389391,
                         'p': 86171467944154384762405147922450425872423195171219400197372357783518331285503,
                         'h': 3457709177527316515351546843477108029400810547203142800323827191717885004610,
                         'iNumBits': 256}}
# Alice
h2_keys = {'PrivateKey' : {'g': 36482904938826431026020554131207847903542016549871844870165534499814489562137,
                           'p': 90875932096819552844785556612588613873835546274321893596879958899737144933243,
                           'x': 7944233631008039187005070093408286827218413351278143022878301217995040934857,
                           'iNumBits': 256},
           'PublicKeyTwitter' : '|TPK|äԵոêӔεӭұιϲϚϳԳӤίƝǔՇϢԹႪՍѹěչž|kʓՒվӛɠaUηĎŚӰՑΫQβԱӭԏİΣʤӎʚοĔ|PĐWɽɣЎтѲҼմǖȒÄɱĠΆůąʇHАўœƝʜǑ|Ƌ',
           'PublicKey' : {'g': 36482904938826431026020554131207847903542016549871844870165534499814489562137,
                          'p': 90875932096819552844785556612588613873835546274321893596879958899737144933243,
                          'h': 15133022460434630682730796928323382059448149509228122470007632710200274491318,
                          'iNumBits': 256}}


# This is private, you need to get your own twitter consumer_key, consumer_sec, access_token_sec
try:
    config = configparser.ConfigParser()
    config.read('user_data.ini')
    consumer_key = config['HeteroT1']['consumer_key']
    consumer_sec = config['HeteroT1']['consumer_sec']
    access_tok = config['HeteroT1']['access_tok']
    access_token_sec = config['HeteroT1']['access_token_sec']
    userkeys = True
except:
    userkeys = False


class test_KeyTools(TestCase):
    # tests
    def test_compress_expand(self):
        # round trip compress, decompress public key
        n = random.getrandbits(300)
        short = key_compress(n)
        backagain = key_expand(short)
        # nlen = len(str(n))
        # print (nlen, len(short), float(len(short))/nlen)
        assert n == backagain, (n, short)

    # def test_make_key_pair(self):
    #     make_key_pair(iNumBits=256, iConfidence=32)

    def test_get_public_key(self):
        if userkeys:
            twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
            h1 = get_public_key(twitter, 'heterot1')
            h2 = get_public_key(twitter, 'heterot2')
            # print(h1, h2)
            assert (h1 == h1_keys['PublicKeyTwitter'])
            assert (h2 == h2_keys['PublicKeyTwitter'])

    def test_publickey_compress_expand(self):
        pk = h1_keys['PublicKey']
        #PublicKey(p, g, h, iNumBits)
        pub = PublicKey(pk['p'], pk['g'], pk['h'], pk['iNumBits'])
        twit = make_twitter_public(pub)
        k = '|TPK|àĶʄքĥȔҚȪĞծɳɚԲɘŎĶŦȥŐȈǹүΒǞƨʨ|YҏɦΦșՄōϜЩʢǹʜНǘӹӚτȊěǔŁЀƃʇșț|DɺѝļΛǏΏǳίӬʎödȥӊΰŖęӀǖӜŊѥԿEϰ|Ƌ'
        pubfromtwit = assemble_publickey(twit)
        assert k == twit
        assert pubfromtwit.p == pub.p
        assert pubfromtwit.g == pub.g
        assert pubfromtwit.h == pub.h
        assert pubfromtwit.iNumBits == pub.iNumBits


class test_MessageEncryption(TestCase):
    def test_simple_encrypt_decrypt(self):
        """
        does not use message and key compression
        """
        plaintext = 'Hello Twitter world in 140 characters.'
        pub = assemble_publickey(h1_keys['PublicKeyTwitter'])
        encrypted = encrypt(pub, plaintext)
        # print(encrypted)
        prk = h1_keys['PrivateKey']
        #ints is a tuple if (p, g, x, iNumBits)
        priv = assemble_privatekey((prk['p'], prk['g'], prk['x'], prk['iNumBits']))
        plaintext = decrypt(priv, encrypted)
        print(plaintext)

    def test_EncryptDecryptMessage(self):
        """
        uses message and key compression
        """
        plaintext = 'Hello Twitter world in 140 characters.'
        pub = assemble_publickey(h1_keys['PublicKeyTwitter'])
        encrypted = encrypt_message(plaintext, pub)
        # print(encrypted)
        prk = h1_keys['PrivateKey']
        priv = assemble_privatekey((prk['p'], prk['g'], prk['x'], prk['iNumBits']))
        decrypted = decrypt_message(priv, encrypted, )
        # print(decrypted)
        assert plaintext == decrypted


class test_Messaging(TestCase):
    def test_send_plain_statusupdate(self):
        if userkeys:
            message = 'test_send_statusupdate. Time:  ' + str(d.now())
            twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
            send_status_update(twitter, message)

    def test_ReadPlainStatus(self):
        if userkeys:
            twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
            user_timeline = twitter.get_user_timeline(screen_name='HeteroT1', count=1, exclude_replies=True)
            lastmessage = user_timeline[0]['text']
            assert lastmessage.split(':')[0] == 'test_send_statusupdate. Time'

    def test_SendEncryptedStatusupdate(self):
        if userkeys:
            plaintext = 'Hello Twitter world'
            # keys
            pub = assemble_publickey(h1_keys['PublicKeyTwitter'])
            prk = h1_keys['PrivateKey']
            priv = assemble_privatekey((prk['p'], prk['g'], prk['x'], prk['iNumBits']))
            encrypted = encrypt_message(plaintext, pub)
            # Send
            twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
            print(encrypted)
            send_status_update(twitter, encrypted)
            # read
            user_timeline = twitter.get_user_timeline(screen_name='HeteroT1', count=1, exclude_replies=True)
            lastmessage = user_timeline[0]['text']
            decrypted = decrypt_message(priv, lastmessage)
            print(decrypted)
            assert plaintext == decrypted


class test_Elgamal(TestCase):
    def id_generator(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def test_roundtrip_plain(self):
        keys = generate_keys()
        priv = keys['privateKey']
        pub = keys['publicKey']
        c = 0
        while c < 1000:
            # message = "My name is Ryan.  Here is some french text:  Maître Corbeau, sur un arbre perché.  Now some Chinese: 鋈 晛桼桾 枲柊氠 藶藽 歾炂盵 犈犆犅 壾, 軹軦軵 寁崏庲 摮 蟼襛 蝩覤 蜭蜸覟 駽髾髽 忷扴汥 "
            message = self.id_generator(500)
            cipher = encrypt(pub, message)
            plain = decrypt(priv, cipher)
            assert message == plain
            c += 1

    def test_roundtrip_stored_key(self):
        puk = h1_keys['PublicKey']
        pub = PublicKey(puk['p'], puk['g'], puk['h'], puk['iNumBits'])
        prk = h1_keys['PrivateKey']
        priv = assemble_privatekey((prk['p'], prk['g'], prk['x'], prk['iNumBits']))
        c = 0
        while c < 100:
            # message = "My name is Ryan.  Here is some french text:  Maître Corbeau, sur un arbre perché.  Now some Chinese: 鋈 晛桼桾 枲柊氠 藶藽 歾炂盵 犈犆犅 壾, 軹軦軵 寁崏庲 摮 蟼襛 蝩覤 蜭蜸覟 駽髾髽 忷扴汥 "
            message = self.id_generator(500)
            cipher = encrypt(pub, message)
            plain = decrypt(priv, cipher)
            assert message == plain
            c += 1

    def test_roundtrip_stored_twitter_key(self):
        pub = assemble_publickey(h1_keys['PublicKeyTwitter'])
        prk = h1_keys['PrivateKey']
        priv = assemble_privatekey((prk['p'], prk['g'], prk['x'], prk['iNumBits']))
        c = 0
        while c < 100:
            # message = "My name is Ryan.  Here is some french text:  Maître Corbeau, sur un arbre perché.  Now some Chinese: 鋈 晛桼桾 枲柊氠 藶藽 歾炂盵 犈犆犅 壾, 軹軦軵 寁崏庲 摮 蟼襛 蝩覤 蜭蜸覟 駽髾髽 忷扴汥 "
            message = self.id_generator(500)
            cipher = encrypt(pub, message)
            plain = decrypt(priv, cipher)
            assert message == plain
            c += 1
