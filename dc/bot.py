
class DCHubBot(DCHubUser):
    '''Bot that runs in the same process as the hub

    When making DCHubBot subclasses, if you place it in the bots directory and
    do not want the bot to appear in the hub, set it's active attribute to
    False.  This will be useful if you are further subclassing that bot and
    don't want the bot itself to appear in the hub.
    '''
    active = True
    isDCHubBot = True
    def __init__(self, hub, nick = 'DCHubBot'):
        DCHubUser.__init__(self)
        self.hub = hub
        self.nick = nick
        self.ignoremessages = True
        self.idstring = 'DCHubBot/%s' % nick
        self.myinfo = myinfoformat % (self.nick, self.description, self.tag, self.speed, chr(self.speedclass), self.email, self.sharesize)
        # If invisble, doesn't show up in user list
        self.visible = True
        # If not an op, show up as regular user instead
        self.op = True
        # Hub functions to wrap or replace
        self.replace, self.execbefore, self.execafter = {}, {}, {}
        hub.setuplimits(self)

    def processcommand(self, user, command):
        '''Process command given to bot via private message'''
        ######## JohnDoe
        if self.nick == 'Genie':
            self.hub.got_Genie(user,command,'give_PrivateMessage')
        if self.nick == 'TVInfo':
            self.hub.got_TVInfo(user,command)
        ######## JohnDoe
        pass

    def start(self):
        '''Initialize hub environment for bot'''
        pass
