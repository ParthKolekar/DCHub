import time

class DCHubUser(object):
    '''Any user of a DC Hub (client or bot)'''

    def __init__(self):
        self.nick = None
        self.version = ''
        self.description = ''
        self.tag = ''
        self.ip = ''
        self.speed = '56Kbps'
        self.speedclass = 1
        self.email = ''
        self.sharesize = 0
        self.myinfo = ''
        self.lastcommandtime = time.time()
        self.ignoremessages = False
        self.givenicklist = False
        self.starttime = time.time()
        self.supports = []
        # Limits for each user, usually the same as the hub's defaults
        self.limits = {}

    def close(self):
        pass

    def sendmessage(self, message):
        pass

