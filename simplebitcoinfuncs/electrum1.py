#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import division
import os
import hashlib
import datetime
from binascii import hexlify, unhexlify
try:
    from .hexhashes import *
    from .base58 import *
    from .miscfuncs import *
    from .miscbitcoinfuncs import *
    from .bitcoin import *
except ValueError:
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *
except SystemError:
    from hexhashes import *
    from base58 import *
    from miscfuncs import *
    from miscbitcoinfuncs import *
    from bitcoin import *


class Electrum1(object):
    def __init__(self,generator=None):
        if generator is None:
            self.seed = hash256(hexlify(os.urandom(40) + \
                        str(datetime.datetime.now()).encode("utf-8")))[:32]
        else:
            try:
                self.seed = hexstrlify(unhexlify(generator))
                assert len(self.seed) == 32
            except:
                try:
                    self.seed = Electrum1.wordstohex(generator)
                    assert len(self.seed) == 32
                except:
                    raise Exception("Input must be a string of hex, a " + \
                                    "word list (lowercase, separated by " + \
                                    "a space), or no input to generate " + \
                                    "a new random seed.")
        self.words = Electrum1.hextowords(self.seed)
        self.mpriv = hexlify(bytearray(self.seed,'utf-8'))
        for i in range(100000):
            self.mpriv = hexlify(hashlib.sha256(unhexlify(self.mpriv + \
                                 hexlify(bytearray(self.seed,'utf-8')))).digest())
        self.mpriv = strlify(self.mpriv)
        self.mpub = privtopub(self.mpriv,False)[2:]

    def __str__(self):
        return self.words

    def __repr__(self):
        return self.words

    def __getitem__(self, a):
        '''
        Retrieves a tuple of private wif key, pubkey, and address for
        a given index. If the input index is an int, it gets the main
        address index, if it's a float (0.0 or 1.0), it gets change
        address info.
        '''

        if 'float' == type(a).__name__:
            ischange = True
            a = int(a)
        elif isitint(a):
            ischange = False
        else:
            raise Exception("Invalid __getitem__() input.")
        return self.priv(a,ischange), self.pub(a,ischange), self.address(a,ischange)

    def child(self,index,change=False):
        return self.priv(index,change), self.pub(index,change), self.address(index,change)

    def priv(self,index,ischange=False):
        if ischange:
            try:    index = hexstrlify(bytes(str(int(index)) + ":1:"))
            except: index = hexstrlify(bytes(str(int(index)) + ":1:",'utf-8'))
        else:
            try:    index = hexstrlify(bytes(str(int(index)) + ":0:"))
            except: index = hexstrlify(bytes(str(int(index)) + ":0:",'utf-8'))
        offset = hash256(index + self.mpub)
        return b58e('80' + addprivkeys(offset,self.mpriv))

    def pub(self,index,ischange=False):
        if ischange:
            try:    index = hexstrlify(bytes(str(int(index)) + ":1:"))
            except: index = hexstrlify(bytes(str(int(index)) + ":1:",'utf-8'))
        else:
            try:    index = hexstrlify(bytes(str(int(index)) + ":0:"))
            except: index = hexstrlify(bytes(str(int(index)) + ":0:",'utf-8'))
        offset = privtopub(hash256(index + self.mpub),False)
        return addpubs(offset, '04' + self.mpub, False)

    def address(self,index,ischange=False):
        return b58e('00' + hash160(self.pub(index,ischange)))

    @staticmethod
    def hextowords(a):
        o = []
        wordlistlen = len(ELECTRUM_WORDLIST)
        for i in range(len(a) // 8):
            word = a[8*i:8*i+8]
            x = int(word,16)
            w1 = (x % wordlistlen)
            w2 = ((x // wordlistlen) + w1) % wordlistlen
            w3 = ((x // wordlistlen // wordlistlen) + w2) % wordlistlen
            o += [ELECTRUM_WORDLIST[w1],
                  ELECTRUM_WORDLIST[w2],
                  ELECTRUM_WORDLIST[w3]]
        return ' '.join(word for word in o)

    @staticmethod
    def wordstohex(words):
        words = normalize_input(words.lower()).split(" ")
        if words[0] == "":   words.pop(0)
        assert len(words) == 12
        for word in words:
            assert word in ELECTRUM_WORDLIST
        o = ""
        wordlistlen = len(ELECTRUM_WORDLIST)
        for i in range(len(words) // 3):
            word1, word2, word3 = words[3*i:3*i+3]
            w1 = ELECTRUM_WORDLIST.index(word1)
            w2 = (ELECTRUM_WORDLIST.index(word2)) % wordlistlen
            w3 = (ELECTRUM_WORDLIST.index(word3)) % wordlistlen
            o += '%08x'%(w1 + wordlistlen * ((w2-w1)%wordlistlen) + \
                         wordlistlen*wordlistlen*((w3-w2)%wordlistlen))
        o = hexstrlify(unhexlify(o))
        assert len(o) == 32
        return o

    @staticmethod
    def crack(mpub,priv,index=None,privtests=100):
        try:
            mpub = validatepubkey('04' + hexstrlify(unhexlify(mpub)))
            assert mpub and mpub[:2] == '04'
            mpub = mpub[2:]
        except:
            raise Exception("Master public key input invalid.")
        try:
            priv = privtohex(priv)
        except:
            raise Exception("Private key input invalid.")
        starting = 0
        if index is not None:
            starting = int(index)
        for i in range(starting,privtests):
            try:    tmpindex1 = hexstrlify(bytes(str(int(i)) + ":0:"))
            except: tmpindex1 = hexstrlify(bytes(str(int(i)) + ":0:",'utf-8'))
            try:    tmpindex2 = hexstrlify(bytes(str(int(i)) + ":1:"))
            except: tmpindex2 = hexstrlify(bytes(str(int(i)) + ":1:",'utf-8'))
            offset1 = hash256(tmpindex1 + mpub)
            offset2 = hash256(tmpindex2 + mpub)
            newpriv1 = subtractprivkeys(priv,offset1)
            newpriv2 = subtractprivkeys(priv,offset2)
            if privtopub(newpriv1,False)[2:] == mpub:
                return newpriv1
            elif privtopub(newpriv2,False)[2:] == mpub:
                return newpriv2
            elif index is not None:
                return False
        return False


ELECTRUM_WORDLIST = [ \
     'like','just','love','know','never',
     'want','time','out','there','make',
     'look','eye','down','only','think',
     'heart','back','then','into','about',
     'more','away','still','them','take',
     'thing','even','through','long','always',
     'world','too','friend','tell','try',
     'hand','thought','over','here','other',
     'need','smile','again','much','cry',
     'been','night','ever','little','said',
     'end','some','those','around','mind',
     'people','girl','leave','dream','left',
     'turn','myself','give','nothing','really',
     'off','before','something','find','walk',
     'wish','good','once','place','ask',
     'stop','keep','watch','seem','everything',
     'wait','got','yet','made','remember',
     'start','alone','run','hope','maybe',
     'believe','body','hate','after','close',
     'talk','stand','own','each','hurt',
     'help','home','god','soul','new',
     'many','two','inside','should','true',
     'first','fear','mean','better','play',
     'another','gone','change','use','wonder',
     'someone','hair','cold','open','best',
     'any','behind','happen','water','dark',
     'laugh','stay','forever','name','work',
     'show','sky','break','came','deep',
     'door','put','black','together','upon',
     'happy','such','great','white','matter',
     'fill','past','please','burn','cause',
     'enough','touch','moment','soon','voice',
     'scream','anything','stare','sound','red',
     'everyone','hide','kiss','truth','death',
     'beautiful','mine','blood','broken','very',
     'pass','next','forget','tree','wrong',
     'air','mother','understand','lip','hit',
     'wall','memory','sleep','free','high',
     'realize','school','might','skin','sweet',
     'perfect','blue','kill','breath','dance',
     'against','fly','between','grow','strong',
     'under','listen','bring','sometimes','speak',
     'pull','person','become','family','begin',
     'ground','real','small','father','sure',
     'feet','rest','young','finally','land',
     'across','today','different','guy','line',
     'fire','reason','reach','second','slowly',
     'write','eat','smell','mouth','step',
     'learn','three','floor','promise','breathe',
     'darkness','push','earth','guess','save',
     'song','above','along','both','color',
     'house','almost','sorry','anymore','brother',
     'okay','dear','game','fade','already',
     'apart','warm','beauty','heard','notice',
     'question','shine','began','piece','whole',
     'shadow','secret','street','within','finger',
     'point','morning','whisper','child','moon',
     'green','story','glass','kid','silence',
     'since','soft','yourself','empty','shall',
     'angel','answer','baby','bright','dad',
     'path','worry','hour','drop','follow',
     'power','war','half','flow','heaven',
     'act','chance','fact','least','tired',
     'children','near','quite','afraid','rise',
     'sea','taste','window','cover','nice',
     'trust','lot','sad','cool','force',
     'peace','return','blind','easy','ready',
     'roll','rose','drive','held','music',
     'beneath','hang','mom','paint','emotion',
     'quiet','clear','cloud','few','pretty',
     'bird','outside','paper','picture','front',
     'rock','simple','anyone','meant','reality',
     'road','sense','waste','bit','leaf',
     'thank','happiness','meet','men','smoke',
     'truly','decide','self','age','book',
     'form','alive','carry','escape','damn',
     'instead','able','ice','minute','throw',
     'catch','leg','ring','course','goodbye',
     'lead','poem','sick','corner','desire',
     'known','problem','remind','shoulder','suppose',
     'toward','wave','drink','jump','woman',
     'pretend','sister','week','human','joy',
     'crack','grey','pray','surprise','dry',
     'knee','less','search','bleed','caught',
     'clean','embrace','future','king','son',
     'sorrow','chest','hug','remain','sat',
     'worth','blow','daddy','final','parent',
     'tight','also','create','lonely','safe',
     'cross','dress','evil','silent','bone',
     'fate','perhaps','anger','class','scar',
     'snow','tiny','tonight','continue','control',
     'dog','edge','mirror','month','suddenly',
     'comfort','given','loud','quickly','gaze',
     'plan','rush','stone','town','battle',
     'ignore','spirit','stood','stupid','yours',
     'brown','build','dust','hey','kept',
     'pay','phone','twist','although','ball',
     'beyond','hidden','nose','taken','fail',
     'float','pure','somehow','wash','wrap',
     'angry','cheek','creature','forgotten','heat',
     'rip','single','space','special','weak',
     'whatever','yell','anyway','blame','job',
     'choose','country','curse','drift','echo',
     'figure','grew','laughter','neck','suffer',
     'worse','yeah','disappear','foot','forward',
     'knife','mess','somewhere','stomach','storm',
     'beg','idea','lift','offer','breeze',
     'field','five','often','simply','stuck',
     'win','allow','confuse','enjoy','except',
     'flower','seek','strength','calm','grin',
     'gun','heavy','hill','large','ocean',
     'shoe','sigh','straight','summer','tongue',
     'accept','crazy','everyday','exist','grass',
     'mistake','sent','shut','surround','table',
     'ache','brain','destroy','heal','nature',
     'shout','sign','stain','choice','doubt',
     'glance','glow','mountain','queen','stranger',
     'throat','tomorrow','city','either','fish',
     'flame','rather','shape','spin','spread',
     'ash','distance','finish','image','imagine',
     'important','nobody','shatter','warmth','became',
     'feed','flesh','funny','lust','shirt',
     'trouble','yellow','attention','bare','bite',
     'money','protect','amaze','appear','born',
     'choke','completely','daughter','fresh','friendship',
     'gentle','probably','six','deserve','expect',
     'grab','middle','nightmare','river','thousand',
     'weight','worst','wound','barely','bottle',
     'cream','regret','relationship','stick','test',
     'crush','endless','fault','itself','rule',
     'spill','art','circle','join','kick',
     'mask','master','passion','quick','raise',
     'smooth','unless','wander','actually','broke',
     'chair','deal','favorite','gift','note',
     'number','sweat','box','chill','clothes',
     'lady','mark','park','poor','sadness',
     'tie','animal','belong','brush','consume',
     'dawn','forest','innocent','pen','pride',
     'stream','thick','clay','complete','count',
     'draw','faith','press','silver','struggle',
     'surface','taught','teach','wet','bless',
     'chase','climb','enter','letter','melt',
     'metal','movie','stretch','swing','vision',
     'wife','beside','crash','forgot','guide',
     'haunt','joke','knock','plant','pour',
     'prove','reveal','steal','stuff','trip',
     'wood','wrist','bother','bottom','crawl',
     'crowd','fix','forgive','frown','grace',
     'loose','lucky','party','release','surely',
     'survive','teacher','gently','grip','speed',
     'suicide','travel','treat','vein','written',
     'cage','chain','conversation','date','enemy',
     'however','interest','million','page','pink',
     'proud','sway','themselves','winter','church',
     'cruel','cup','demon','experience','freedom',
     'pair','pop','purpose','respect','shoot',
     'softly','state','strange','bar','birth',
     'curl','dirt','excuse','lord','lovely',
     'monster','order','pack','pants','pool',
     'scene','seven','shame','slide','ugly',
     'among','blade','blonde','closet','creek',
     'deny','drug','eternity','gain','grade',
     'handle','key','linger','pale','prepare',
     'swallow','swim','tremble','wheel','won',
     'cast','cigarette','claim','college','direction',
     'dirty','gather','ghost','hundred','loss',
     'lung','orange','present','swear','swirl',
     'twice','wild','bitter','blanket','doctor',
     'everywhere','flash','grown','knowledge','numb',
     'pressure','radio','repeat','ruin','spend',
     'unknown','buy','clock','devil','early',
     'false','fantasy','pound','precious','refuse',
     'sheet','teeth','welcome','add','ahead',
     'block','bury','caress','content','depth',
     'despite','distant','marry','purple','threw',
     'whenever','bomb','dull','easily','grasp',
     'hospital','innocence','normal','receive','reply',
     'rhyme','shade','someday','sword','toe',
     'visit','asleep','bought','center','consider',
     'flat','hero','history','ink','insane',
     'muscle','mystery','pocket','reflection','shove',
     'silently','smart','soldier','spot','stress',
     'train','type','view','whether','bus',
     'energy','explain','holy','hunger','inch',
     'magic','mix','noise','nowhere','prayer',
     'presence','shock','snap','spider','study',
     'thunder','trail','admit','agree','bag',
     'bang','bound','butterfly','cute','exactly',
     'explode','familiar','fold','further','pierce',
     'reflect','scent','selfish','sharp','sink',
     'spring','stumble','universe','weep','women',
     'wonderful','action','ancient','attempt','avoid',
     'birthday','branch','chocolate','core','depress',
     'drunk','especially','focus','fruit','honest',
     'match','palm','perfectly','pillow','pity',
     'poison','roar','shift','slightly','thump',
     'truck','tune','twenty','unable','wipe',
     'wrote','coat','constant','dinner','drove',
     'egg','eternal','flight','flood','frame',
     'freak','gasp','glad','hollow','motion',
     'peer','plastic','root','screen','season',
     'sting','strike','team','unlike','victim',
     'volume','warn','weird','attack','await',
     'awake','built','charm','crave','despair',
     'fought','grant','grief','horse','limit',
     'message','ripple','sanity','scatter','serve',
     'split','string','trick','annoy','blur',
     'boat','brave','clearly','cling','connect',
     'fist','forth','imagination','iron','jock',
     'judge','lesson','milk','misery','nail',
     'naked','ourselves','poet','possible','princess',
     'sail','size','snake','society','stroke',
     'torture','toss','trace','wise','bloom',
     'bullet','cell','check','cost','darling',
     'during','footstep','fragile','hallway','hardly',
     'horizon','invisible','journey','midnight','mud',
     'nod','pause','relax','shiver','sudden',
     'value','youth','abuse','admire','blink',
     'breast','bruise','constantly','couple','creep',
     'curve','difference','dumb','emptiness','gotta',
     'honor','plain','planet','recall','rub',
     'ship','slam','soar','somebody','tightly',
     'weather','adore','approach','bond','bread',
     'burst','candle','coffee','cousin','crime',
     'desert','flutter','frozen','grand','heel',
     'hello','language','level','movement','pleasure',
     'powerful','random','rhythm','settle','silly',
     'slap','sort','spoken','steel','threaten',
     'tumble','upset','aside','awkward','bee',
     'blank','board','button','card','carefully',
     'complain','crap','deeply','discover','drag',
     'dread','effort','entire','fairy','giant',
     'gotten','greet','illusion','jeans','leap',
     'liquid','march','mend','nervous','nine',
     'replace','rope','spine','stole','terror',
     'accident','apple','balance','boom','childhood',
     'collect','demand','depression','eventually','faint',
     'glare','goal','group','honey','kitchen',
     'laid','limb','machine','mere','mold',
     'murder','nerve','painful','poetry','prince',
     'rabbit','shelter','shore','shower','soothe',
     'stair','steady','sunlight','tangle','tease',
     'treasure','uncle','begun','bliss','canvas',
     'cheer','claw','clutch','commit','crimson',
     'crystal','delight','doll','existence','express',
     'fog','football','gay','goose','guard',
     'hatred','illuminate','mass','math','mourn',
     'rich','rough','skip','stir','student',
     'style','support','thorn','tough','yard',
     'yearn','yesterday','advice','appreciate','autumn',
     'bank','beam','bowl','capture','carve',
     'collapse','confusion','creation','dove','feather',
     'girlfriend','glory','government','harsh','hop',
     'inner','loser','moonlight','neighbor','neither',
     'peach','pig','praise','screw','shield',
     'shimmer','sneak','stab','subject','throughout',
     'thrown','tower','twirl','wow','army',
     'arrive','bathroom','bump','cease','cookie',
     'couch','courage','dim','guilt','howl',
     'hum','husband','insult','led','lunch',
     'mock','mostly','natural','nearly','needle',
     'nerd','peaceful','perfection','pile','price',
     'remove','roam','sanctuary','serious','shiny',
     'shook','sob','stolen','tap','vain',
     'void','warrior','wrinkle','affection','apologize',
     'blossom','bounce','bridge','cheap','crumble',
     'decision','descend','desperately','dig','dot',
     'flip','frighten','heartbeat','huge','lazy',
     'lick','odd','opinion','process','puzzle',
     'quietly','retreat','score','sentence','separate',
     'situation','skill','soak','square','stray',
     'taint','task','tide','underneath','veil',
     'whistle','anywhere','bedroom','bid','bloody',
     'burden','careful','compare','concern','curtain',
     'decay','defeat','describe','double','dreamer',
     'driver','dwell','evening','flare','flicker',
     'grandma','guitar','harm','horrible','hungry',
     'indeed','lace','melody','monkey','nation',
     'object','obviously','rainbow','salt','scratch',
     'shown','shy','stage','stun','third',
     'tickle','useless','weakness','worship','worthless',
     'afternoon','beard','boyfriend','bubble','busy',
     'certain','chin','concrete','desk','diamond',
     'doom','drawn','due','felicity','freeze',
     'frost','garden','glide','harmony','hopefully',
     'hunt','jealous','lightning','mama','mercy',
     'peel','physical','position','pulse','punch',
     'quit','rant','respond','salty','sane',
     'satisfy','savior','sheep','slept','social',
     'sport','tuck','utter','valley','wolf',
     'aim','alas','alter','arrow','awaken',
     'beaten','belief','brand','ceiling','cheese',
     'clue','confidence','connection','daily','disguise',
     'eager','erase','essence','everytime','expression',
     'fan','flag','flirt','foul','fur',
     'giggle','glorious','ignorance','law','lifeless',
     'measure','mighty','muse','north','opposite',
     'paradise','patience','patient','pencil','petal',
     'plate','ponder','possibly','practice','slice',
     'spell','stock','strife','strip','suffocate',
     'suit','tender','tool','trade','velvet',
     'verse','waist','witch','aunt','bench',
     'bold','cap','certainly','click','companion',
     'creator','dart','delicate','determine','dish',
     'dragon','drama','drum','dude','everybody',
     'feast','forehead','former','fright','fully',
     'gas','hook','hurl','invite','juice',
     'manage','moral','possess','raw','rebel',
     'royal','scale','scary','several','slight',
     'stubborn','swell','talent','tea','terrible',
     'thread','torment','trickle','usually','vast',
     'violence','weave','acid','agony','ashamed',
     'awe','belly','blend','blush','character',
     'cheat','common','company','coward','creak',
     'danger','deadly','defense','define','depend',
     'desperate','destination','dew','duck','dusty',
     'embarrass','engine','example','explore','foe',
     'freely','frustrate','generation','glove','guilty',
     'health','hurry','idiot','impossible','inhale',
     'jaw','kingdom','mention','mist','moan',
     'mumble','mutter','observe','ode','pathetic',
     'pattern','pie','prefer','puff','rape',
     'rare','revenge','rude','scrape','spiral',
     'squeeze','strain','sunset','suspend','sympathy',
     'thigh','throne','total','unseen','weapon',
     'weary']

