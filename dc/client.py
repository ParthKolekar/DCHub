from .user import DCHubUser
import time

class DCHubClient(DCHubUser):
    '''Client connecting to the hub'''

    def __init__(self, struct):
        sock, (ip, port) = struct
        DCHubUser.__init__(self)
        self.socket = sock
        self.socketid = sock.fileno()
        self.account = None
        self.ip = ip
        self.port = port
        self.key = ''
        self.loggedin = False
        self.op = False
        self.idstring = '%s:%s/' % (self.ip, self.port)
        myinfoformat = '$MyINFO $ALL %s %s%s$ $%s%s$%s$%i$|'
        self.myinfo = myinfoformat % (self.nick, self.description, self.tag, self.speed, chr(self.speedclass), self.email, self.sharesize)
        self.validcommands = set('Key Supports ValidateNick'.split())
        # Necessary for spam/flood prevention
        self.recentmessages, self.searchtimes, self.myinfotimes = [], [], []
        self.commandtimes = []
        # Incoming and outgoing buffers for client
        self.incoming = ['']
        self.outgoing = ''

    def close(self):
        '''Close related socket connection'''
        self.socket.close()

    def sendmessage(self, message):
        '''Place a message in the outgoing message buffer for the user'''
        if not self.ignoremessages:
            self.outgoing += message
            self.lastcommandtime = time.time()
