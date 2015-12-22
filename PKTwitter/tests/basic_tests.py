import configparser
import random
import string
from datetime import datetime as d
from unittest import TestCase

from PKTwitter.messaging import encrypt_message, decrypt_message, send_status_update
from twython import Twython

from PKTwitter.elgamal2 import PublicKey, encrypt, decrypt, generate_keys
from PKTwitter.key_tools import key_compress, key_expand, get_public_key, assemblePublicKeyElgamal, assemblePrivateKeyElgamal, make_twitter_public

h1_key = {'PrivateKey': (58504424099595153091358344215955475230050049863512430651997500754387780518083,
                         38614024321110971174729173348335841809565219369323123741355000936927396786103,
                         39730116072721460806461502394040814760430228006424332182977094853608328496076,
                         256), 'PublicKeyTwitter': '|TPK|ÅʎȾïκĦçǼǭŤԫɱųyxӏʗɄϲՖʊњșѴʝß|mύYǖûԼĻсĺǱǤҹҙΛŨȇǘĈэǹAԘԏȢѺó|rԝӄăȃǼąЏœϲӋӳʓевкЪЗԧúҾƇՍКϛӗ|ƍ',
          'PublicKey': (58504424099595153091358344215955475230050049863512430651997500754387780518083,
                        38614024321110971174729173348335841809565219369323123741355000936927396786103,
                        43941852118365358120679198651859899509717714722706687951109846250988690628871,
                        256
                        )}

h2_key = dict(PrivateKey=(64920886194952987256412246312819798284641846100168300883020957925738043123223,
                          40286097406928106390665231019035371289374310946194041291156901633994826301988,
                          12451816743310384350839455290582814769468821404604129753069361124628871636399,
                          256), PublicKeyTwitter='|TPK|ËԈӦŏԨՌƍȲƃǍңҎƩϨҾðĵƹӣUԭԍъrĈŬ|oƫíȬԐöȜЁŴTjȉƮȌǊԢŏpưĩӵϠՓҪƺՍ|MəҠяǊȖǴҷɝƯέҞѩɪҥȪσĎљÐǿĉϛӗϣȥ|ƍ',
              PublicKey=(64920886194952987256412246312819798284641846100168300883020957925738043123223,
                         40286097406928106390665231019035371289374310946194041291156901633994826301988,
                         26411613147959710735752662179675054173684751574803940945905190516099282103410,
                         256
                         ))


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
        twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
        h1 = get_public_key(twitter, 'heterot1')
        h2 = get_public_key(twitter, 'heterot2')
        # print(h1, h2)
        assert(h1 == h1_key['PublicKeyTwitter'])
        assert(h2 == h2_key['PublicKeyTwitter'])

    def test_publickey_compress_expand(self):
        orgkey = PublicKey(h1_key['PublicKey'][0], h1_key['PublicKey'][1], h1_key['PublicKey'][2], h1_key['PublicKey'][3])
        twitkey = make_twitter_public(orgkey)
        k = '|TPK|ÅʎȾïκĦçǼǭŤԫɱųyxӏʗɄϲՖʊњșѴʝß|mύYǖûԼĻсĺǱǤҹҙΛŨȇǘĈэǹAԘԏȢѺó|rԝӄăȃǼąЏœϲӋӳʓевкЪЗԧúҾƇՍКϛӗ|ƍ'
        twitkeyback = assemblePublicKeyElgamal(twitkey)
        assert k == twitkey
        assert twitkeyback.p == orgkey.p
        assert twitkeyback.g == orgkey.g
        assert twitkeyback.h == orgkey.h
        assert twitkeyback.iNumBits == orgkey.iNumBits


class test_messageEncryption(TestCase):

    def test_simple_encrypt_decrypt(self):
        """
        does not use message and key compression
        """
        plaintext = 'Hello Twitter world in 140 characters.'
        h1_Pub = assemblePublicKeyElgamal(h1_key['PublicKeyTwitter'])
        encrypted = encrypt(h1_Pub, plaintext)
        # print(encrypted)
        h1_priv = assemblePrivateKeyElgamal(h1_key['PrivateKey'])
        plaintext = decrypt(h1_priv, encrypted)
        print(plaintext)

    def test_encrypt_decrypt_message(self):
        """
        uses message and key compression
        """
        plaintext = 'Hello Twitter world in 140 characters.'
        h1_Publickey = assemblePublicKeyElgamal(h1_key['PublicKeyTwitter'])
        encrypted = encrypt_message(plaintext, h1_Publickey)
        # print(encrypted)
        h1_Privatekey = assemblePrivateKeyElgamal(h1_key['PrivateKey'])
        decrypted = decrypt_message(h1_Privatekey, encrypted,)
        # print(decrypted)
        assert plaintext == decrypted


class test_messaging(TestCase):

    def test_send_plain_statusupdate(self):
        message = 'test_send_statusupdate. Time:  ' + str(d.now())
        twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
        send_status_update(twitter, message)

    def test_read_plain_status(self):
        twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
        user_timeline = twitter.get_user_timeline(screen_name='HeteroT1', count=1, exclude_replies=True)
        lastmessage = user_timeline[0]['text']
        assert lastmessage.split(':')[0] == 'test_send_statusupdate. Time'

    def test_send_encrypted_statusupdate(self):
        plaintext = 'Hello Twitter world'
        # keys
        h1_Publickey = assemblePublicKeyElgamal(h1_key['PublicKeyTwitter'])
        h1_Privatekey = assemblePrivateKeyElgamal(h1_key['PrivateKey'])
        encrypted = encrypt_message(plaintext, h1_Publickey)
        # Send
        twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
        print(encrypted)
        send_status_update(twitter, encrypted)
        # read
        user_timeline = twitter.get_user_timeline(screen_name='HeteroT1', count=1, exclude_replies=True)
        lastmessage = user_timeline[0]['text']
        decrypted = decrypt_message(h1_Privatekey, lastmessage,)
        print(decrypted)
        assert plaintext == decrypted




class test_elgamal(TestCase):

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
        Pub = PublicKey(h1_key['PublicKey'][0], h1_key['PublicKey'][1], h1_key['PublicKey'][2], h1_key['PublicKey'][3])
        h1_Privatekey = assemblePrivateKeyElgamal(h1_key['PrivateKey'])
        c = 0
        while c < 100:
            # message = "My name is Ryan.  Here is some french text:  Maître Corbeau, sur un arbre perché.  Now some Chinese: 鋈 晛桼桾 枲柊氠 藶藽 歾炂盵 犈犆犅 壾, 軹軦軵 寁崏庲 摮 蟼襛 蝩覤 蜭蜸覟 駽髾髽 忷扴汥 "
            message = self.id_generator(500)
            cipher = encrypt(Pub, message)
            plain = decrypt(h1_Privatekey, cipher)
            assert message == plain
            c += 1

    def test_roundtrip_stored_twitter_key(self):
        h1_Publickey = assemblePublicKeyElgamal(h1_key['PublicKeyTwitter'])
        h1_Privatekey = assemblePrivateKeyElgamal(h1_key['PrivateKey'])
        c = 0
        while c < 100:
            # message = "My name is Ryan.  Here is some french text:  Maître Corbeau, sur un arbre perché.  Now some Chinese: 鋈 晛桼桾 枲柊氠 藶藽 歾炂盵 犈犆犅 壾, 軹軦軵 寁崏庲 摮 蟼襛 蝩覤 蜭蜸覟 駽髾髽 忷扴汥 "
            message = self.id_generator(500)
            cipher = encrypt(h1_Publickey, message)
            plain = decrypt(h1_Privatekey, cipher)
            assert message == plain
            c += 1
