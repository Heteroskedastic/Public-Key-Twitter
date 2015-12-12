from unittest import TestCase
import configparser
import random
from key_tools import key_compress, key_expand, get_public_key, make_key_pair
from twython import Twython
from messaging import send_status_update

h1_key = {'PrivateKey':
              (58504424099595153091358344215955475230050049863512430651997500754387780518083,
               38614024321110971174729173348335841809565219369323123741355000936927396786103,
               39730116072721460806461502394040814760430228006424332182977094853608328496076,
               256),
          'PublicKeyTwitter':
              '|TPK|ÅʎȾïκĦçǼǭŤԫɱųyxӏʗɄϲՖʊњșѴʝß|mύYǖûԼĻсĺǱǤҹҙΛŨȇǘĈэǹAԘԏȢѺó|rԝӄăȃǼąЏœϲӋӳʓевкЪЗԧúҾƇՍКϛӗ|ƍ',
          'PublicKey':
              (58504424099595153091358344215955475230050049863512430651997500754387780518083,
               38614024321110971174729173348335841809565219369323123741355000936927396786103,
               43941852118365358120679198651859899509717714722706687951109846250988690628871,
               )}

h2_key = {'PrivateKey':
              (64920886194952987256412246312819798284641846100168300883020957925738043123223,
               40286097406928106390665231019035371289374310946194041291156901633994826301988,
               12451816743310384350839455290582814769468821404604129753069361124628871636399),
          'PublicKeyTwitter':
              '|TPK|ËԈӦŏԨՌƍȲƃǍңҎƩϨҾðĵƹӣUԭԍъrĈŬ|oƫíȬԐöȜЁŴTjȉƮȌǊԢŏpưĩӵϠՓҪƺՍ|aȱόĠԯЮчјϾŀЋÁĺДїΥғԜԡӹŋʛïƧóȰ|ƍ',
          'PublicKey':
              (64920886194952987256412246312819798284641846100168300883020957925738043123223,
               40286097406928106390665231019035371289374310946194041291156901633994826301988,
               26411613147959710735752662179675054173684751574803940945905190516099282103410)}

config = configparser.ConfigParser()
config.read('user_data.ini')
consumer_key = config['HeteroT1']['consumer_key']
consumer_sec = config['HeteroT1']['consumer_sec']
access_tok = config['HeteroT1']['access_tok']
access_token_sec = config['HeteroT1']['access_token_sec']

class test_key_tools(TestCase):
    # tests
    def test_public_key_coding(self):
        #round trip compress, decompress public key
        n = random.getrandbits(300)
        short = key_compress(n)
        backagain = key_expand(short)
        nlen = len(str(n))
        #print (nlen, len(short), float(len(short))/nlen)
        assert n == backagain, (n,short)

    def test_make_key_pair(self):
        make_key_pair(iNumBits=256, iConfidence=32)


    def test_get_public_key(self):
        twitter = Twython(consumer_key, consumer_sec, access_tok, access_token_sec)
        h1 = get_public_key(twitter, 'heterot1')
        h2 = get_public_key(twitter, 'heterot2')
        #print(h1[1:], h2[1:])
        assert(h1[1:] == h1_key['PublicKey'])
        assert(h2[1:] == h2_key['PublicKey'])

# send_status_update(consumer_key, consumer_sec, access_tok, access_token_sec)
# print(k)

