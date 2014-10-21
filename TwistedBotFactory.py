
from twisted.words.protocols import irc
from twisted.internet import protocol
import traceback,sys
import collections
import shlex

class Bot(irc.IRCClient):
    def __init__(self):
        self._is_signed_on = False
    
        self._joined_channels = set()
        self._msg_queue = []
        self.command_modules = {}
        self.signed_on_cbs = []
        self.joined_channel_cbs = []
        self.privmsg_monitors = []
    
        
    def _get_nickname(self):
        return self.factory.nickname
    nickname = property(_get_nickname)

    def install_command_module(self,name,command_module):
        assert name not in self.command_modules
        
        self.command_modules[name] = command_module
        
        command_module.config = self.main_context['config']
        command_module.main_context = self.main_context
        command_module.bot = self


    def poll_msg_queue(self):
        if not self.is_signed_on():
            return
        
        next_msg_queue = []
        
        for msg in self._msg_queue:
            
            if not self.is_signed_on():
                next_msg_queue += [msg]
                continue
            user,message,length = msg
            
            #print
            #print
            #print 'for \'{msg}\' in self._msg_queue'.format(msg=msg)
            #print
            #print
            
            if len(user) == 0:
                continue
            if user[0] != '#':
                self.msg(user,message,length)
                continue
            
            channel = user
            
            if channel not in self._joined_channels:
                next_msg_queue += [msg]
                continue
            self.msg(channel,message,length)
        self._msg_queue = next_msg_queue
            
            
    def queue_msg(self,user,message,length=None):
        #print 'queue_msg({user},{message},{length})'.format(user=user,message=message,length=length)
        self._msg_queue.append((user,message,length))

    def receivedMOTD(self, motd):
        print 'receivedMOTD()'
        #print '\n'.join(motd)
        
        print 'sending join command, self.factory.channel:',self.factory.channel
        self.join(self.factory.channel)

    def lineReceived(self, line):
        print 'lineReceived({line})'.format(line=line)
        irc.IRCClient.lineReceived(self,line)
        

    def signedOn(self):
        #print 'self.factory.channel:',self.factory.channel
        
        self._is_signed_on = True
        
        print "Signed on as %s." % (self.nickname,)
        
        
        for cb in self.signed_on_cbs:
            try:
                cb(self)
            except Exception as e:
                
                print 'Exception while calling signed_on_cbs, e:',e
                print 'cb:',cb
                
                traceback.print_exc(file=sys.stdout)
                continue
                
        
        """
        {channel => {nick => host}}
        """
        self.channel_nicks = {}

    def is_signed_on(self):
        return self._is_signed_on
    
    def joined(self, channel):
        print "Joined %s." % (channel,)
        
        self._joined_channels.add(channel)
        
        
        for cb in self.joined_channel_cbs:
            try:
                cb(self)
            except Exception as e:
                
                print 'Exception while calling joined_channel_cbs, e:',e
                print 'cb:',cb
                
                traceback.print_exc(file=sys.stdout)
                continue
                
        
    def left(self, channel):
        print "Left %s." % (channel,)
        
        self._joined_channels.discard(channel)
    
    def kickedFrom(self, channel, kicker, message):
        self.joined_channels.discard(channel)
    
    """
    def names(self, channel):
        "List the users in 'channel', usage: client.who('#testroom')"
        #self.sendLine('NAMES %s' % channel)
        self.channel_nicks[channel] = {}
        pass
    def irc_RPL_NAMREPLY(self, prefix, params):
        print 'irc_RPL_NAMREPLY({prefix},{params})'.format(prefix=prefix,params=params)
        
        channel = params[2]
        nicks = params[3].strip().split(' ')
        
        
        this_channel_nicks = self.channel_nicks[channel]
        for nick in nicks:
            this_channel_nicks.add(nick)
        
        print 'self.channel_nicks:',self.channel_nicks
    def irc_RPL_ENDOFNAMES(self, prefix, params):
        print 'irc_RPL_ENDOFNAMES({prefix},{params})'.format(prefix=prefix,params=params)

    def joined(self, channel):
        #print "Joined %s." % (channel,)
        self.names(channel)
        pass

    def remember_user(self,user,channel):
        channel_nicks = self.channel_nicks
        if channel not in channel_nicks:
            channel_nicks[channel] = set()
        
        nick,_,_ = user.partition('!')
        channel_nicks[channel] |= set([nick])
        
    def forget_user(self,user, channel):
        channel_nicks = self.channel_nicks
        if channel not in channel_nicks:
            print "WARNING, SOMETHING WRONG IN forget_user(): channel not in channel_nicks"
            return
        
        nick,_,_ = user.partition('!')
        if nick not in channel_nicks[channel]:
            print "WARNING, SOMETHING WRONG IN forget_user(): nick not in channel_nicks[channel]"
            return
        
        channel_nicks[channel].discard(nick)
    
    """
    def userJoined(self,user, channel):
        print 'userJoined({user},{channel})'.format(user=user,channel=channel)
        
        #if channel in self.channel_nicks:
        #    print 'WARNING: userJoined(), channel in self.channel_nicks'
        
        #self.channel_nicks[channel] = set()
        
        #self.remember_user(user,channel)
    """
    def userLeft(self,user, channel):
        print 'userLeft({user},{channel})'.format(user=user,channel=channel)
        self.forget_user(user,channel)
    def userQuit(self,user, channel):
        print 'userQuit({user},{channel})'.format(user=user,channel=channel)
        self.forget_user(user,channel)
    def userKicked(self,user, channel):
        print 'userKicked({user},{channel})'.format(user=user,channel=channel)
        self.forget_user(user,channel)
    def userRenamed(self,oldname, newname):
        channel_nicks = self.channel_nicks
        
        print 'userKicked({oldname},{newname})'.format(newname=newname,oldname=oldname)
        
        
        for channel,nicks in channel_nicks.iteritems():
            
            if oldname in nicks:
                nicks.discard(oldname)
                nicks.add(newname)
        
    """
        

    def print_usage(self,variables,wrong_usage=False):
        
        
        usage = ''
        
        
        cmds = []
        usage_list = []
        for cmd_name,cmd_module in self.command_modules.iteritems():
            try:
                cmds += [cmd_name]
                usage_list += [cmd_module.usage()]
            except Exception as e:
                print 'Exception printing usage of ',cmd_name, 'module:',cmd_module, 'e:',e
                
                traceback.print_exc(file=sys.stdout)
                
                continue
        
        
        usage += '\n\n' + 'Available commands: ' + ' '.join(cmds)
        usage += '\n\n' + 'Usage: \n  ' + '\n  '.join(usage_list) + '\n\n'


        self.msg(variables['usernick'],usage)

        if variables['in_channel']:
            if wrong_usage:
                self.msg(variables['response_channel'], variables['response_prefix'] + 'umm ... wrong usage ... I pm\'d you proper usage!')
            else:
                self.msg(variables['response_channel'], variables['response_prefix'] + 'I pm\'d you the proper usage.')


    def run_command(self,full_cmd,variables):

        args = shlex.split(full_cmd)
        cmd = args[0]
        args = args[1:]
        
        
        if cmd not in self.command_modules:
            self.print_usage(variables,True)
            return
        
        try:
            self.command_modules[cmd].run(cmd,args,variables)
        except Exception as e:
            print e
            
            self.msg(variables['response_channel'], variables['response_prefix'] + 'Error running command, see bot logs')
            raise
    
    def irc_MODE(self, prefix, params):
        #print 'irc_MODE({prefix}, {params})'.format(prefix=prefix,params=params)
        irc.IRCClient.irc_MODE(self,prefix,params)
    def irc_NOTICE(self, prefix, params):
        #print 'irc_NOTICE({prefix}, {params})'.format(prefix=prefix,params=params)
        irc.IRCClient.irc_NOTICE(self,prefix,params)
        
    def irc_RPL_MYINFO(self, prefix, params):
        #print 'irc_RPL_MYINFO({prefix}, {params})'.format(prefix=prefix,params=params)
        irc.IRCClient.irc_RPL_MYINFO(self,prefix,params)
    def irc_RPL_YOURHOST(self, prefix, params):
        #print 'irc_RPL_YOURHOST({prefix}, {params})'.format(prefix=prefix,params=params)
        irc.IRCClient.irc_RPL_YOURHOST(self,prefix,params)
    
    
    
    
    def irc_unknown(self, prefix, command, params):
        #print 'irc_unknown({prefix}, {command}, {params})'.format(prefix=prefix,command=command,params=params)
        irc.IRCClient.irc_unknown(self,prefix, command, params)
    
    def irc_ERR_CHANOPRIVSNEEDED(self,prefix,params):
        #print 'irc_ERR_CHANOPRIVSNEEDED({prefix}, {params})'.format(prefix=prefix,params=params)
        pass
    
    def handleCommand(self, command, prefix, params):
        #print 'handleCommand({command}, {prefix}, {params})'.format(command=command,prefix=prefix,params=params)
        irc.IRCClient.handleCommand(self,command,prefix,params)
        
        
    def privmsg(self, user, channel, msg):
        
        try:
            print channel+'>',user+':',msg
            usernick,_,_ = user.partition('!')
            
            variables = {'nick':self.nickname,'user':user,'usernick':usernick,'response_channel':channel,'channel':channel}
            variables['response_prefix'] = usernick + ': '
            
            """
            #if this is not a pm
            if channel != self.nickname:
                if msg.startswith(self.nickname + ":"):
                    self.msg(channel, usernick+': '+ '/msg me, or pm me, I cannot do business in an open channel.')
                    return
                return
            """
            
            full_cmd = ''
            
            variables['in_channel'] = True
            variables['addresses_me'] = False
            
            #if this is a pm
            if channel == self.nickname:
                
                
                variables['response_channel'] = usernick
                variables['response_prefix'] = ''
                variables['in_channel'] = False
                full_cmd = msg
                
                
                if msg.startswith(self.nickname + ":"):
                    self.msg(variables['response_channel'], variables['response_prefix']+ 'This is a PM, Don\'t prefix your commands with "{botnick}:".'.format(botnick=self.nickname))
                    return
                variables['addresses_me'] = True
                
            elif msg.startswith(self.nickname + ":"):
                full_cmd = msg[ len(self.nickname + ":"): ].strip()
                variables['addresses_me'] = True
                
            for monitor in self.privmsg_monitors:
                try:
                    monitor(self,user,channel,msg,variables)
                except Exception as e:
                    print 'Exception in monitor:',e
                    print 'monitor:',monitor
                    
                    traceback.print_exc(file=sys.stdout)
            
            if not variables['addresses_me']:
                return
            
            
            
            if len(full_cmd) == 0:
                self.msg(channel, 'shhh'.format(**variables))
                return
            
            if full_cmd[0] == '!':
                self.run_command(full_cmd[1:],variables)
                return
            
            full_cmd = full_cmd.lower()
            
            d = { }
            
            
            if full_cmd not in d:
                self.msg(variables['response_channel'], 'Odd, I thought I heard something.'.format(**variables))
                return
            
            self.msg(channel, d[full_cmd].format(**variables))
            
            return
            
                

            pass
        except Exception as e:
            print 'Exception in privmsg:',e
            
            traceback.print_exc(file=sys.stdout)

            



class BotFactory(protocol.ClientFactory):
    protocol = Bot
    
    def buildProtocol(self, addr):
        bot = protocol.ClientFactory.buildProtocol(self,addr)
        self.bots.append(bot)
        bot.main_context = self.main_context
        bot.config = self.config
        
        for cb in self.bot_created_cbs:
            try:
                cb(bot)
            except Exception as e:
                print 'BotFactory.buildProtocol():cb error:',e,'cb:',cb
                traceback.print_exc(file=sys.stdout)
            
        return bot

    def __init__(self, channel, nickname,main_context):
        print 'channel:',channel
        self.channel = channel
        self.nickname = nickname
        self.bots = []
        self.main_context = main_context
        self.config = main_context['config']
        self.bot_created_cbs = []

    def clientConnectionLost(self, connector, reason):
        print "Lost connection (%s), reconnecting." % (reason,)
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        print "Could not connect: %s" % (reason,)
