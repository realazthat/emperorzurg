#!/usr/bin/env python

"""

TODO:

* Colorful announcements

SECURITY:
* check if kick trigers userleft
* If someone identifies, and their hostmask changes, is this detected?

"""

from twisted_irc_modules.command import Command 
from twisted_irc_modules.help import HelpCommand 
import time
import sqlite3

from TwistedBotFactory import BotFactory
from twisted.internet import reactor
import functools
import re
import tool_utils
import urlparse
from ircutils.protocol import is_nick
import yaml
from twisted.internet.task import LoopingCall

class UnauthorizedException(Exception):
    def __init__(user=None,action=None):
        message = ['UnauthorizedException']
        
        if user is not None:
            message += ['user: \'{user}\''.format(user=user)]
        if action is not None:
            message += ['action: \'{action}\''.format(action=action)]
        Exception(self,message)
        
        self.user=user
        self.action=action
        
class ACLReportError(Exception):
    pass

class ACL:
    def __init__(self,main_context):
        self.main_context = main_context
        self.config = self.main_context['config']
        
    """
    def user_can_set(self,user,permission):
        db_conn = self.main_context['db_conn']
        
        c = db_conn.cursor()
        
    
        c.execute( '''SELECT role_set_perms.permission FROM role_set_perms, user_roles, users
                      WHERE role_set_perms.roleid == user_roles.roleid
                        AND user_roles.userid = users.userid
                        AND users.user=?
                        AND role_set_perms.permission=?''', (user,permission))
        
        return False
    """
    def user_has_perm(self,user,permission):
        print 'permission:',permission
        
        usernick,_,username_hostmask = user.partition('!')
        username,_,hostmask = username_hostmask.partition('@')
        
        has_cloak = '/' in hostmask
        if not has_cloak:
            return False
        
        cloak = hostmask
                
        db_conn = self.main_context['db_conn']
        
        c = db_conn.cursor()
        c.execute( '''SELECT permissions.name FROM permissions, role_perms, user_roles, users
                      WHERE permissions.permid = role_perms.permid
                        AND role_perms.roleid = user_roles.roleid
                        AND user_roles.userid = users.userid
                        AND users.cloak=?
                        AND permissions.name=?''', (cloak,permission))
        
        result = c.fetchall()
        
        assert len(result) <= 1
        return len(result) == 1
    
    def cloak_exists(self,cloak):
        db_conn = self.main_context['db_conn']
        c = db_conn.cursor()
        c.execute('''SELECT users.userid
                     FROM users
                     WHERE users.cloak=?''',(cloak,))
        r = c.fetchall()
        
        assert len(r) <= 1
        
        if len(r) == 0:
            return False
        return True
    
    def role_exists(self,role):
        db_conn = self.main_context['db_conn']
        c = db_conn.cursor()
        c.execute('''SELECT roles.roleid
                     FROM roles
                     WHERE roles.name=?''',(role,))
        r = c.fetchall()
        
        assert len(r) <= 1
        
        if len(r) == 0:
            return False
        return True
        
    def add_user_cloak(self,user, new_cloak):
        
        if not self.user_has_perm(user, 'add_user'):
            raise UnauthorizedException(user=user,
                                        action='add_user_cloak({user}, {new_cloak})'.format(
                                            user=user,new_cloak=new_cloak))
        
        
        valid_cloak = '/' in new_cloak
        if not valid_cloak:
            raise ACLReportError('\'{cloak}\' is not a valid cloak'.format(cloak=new_cloak))
        
        db_conn = self.main_context['db_conn']
        
        c = db_conn.cursor()
        
        try:
            if self.cloak_exists(new_cloak):
                raise ACLReportError('\'{new_cloak}\' already exists'.format(new_cloak=new_cloak))
            
            c.execute('''INSERT INTO users (cloak) VALUES (?)''', (new_cloak,))
            
            db_conn.commit()
        except:
            #TODO: catch user existing, and send bot error msg
            raise
        
    def assign_role_to_cloak(self,user, assignee_cloak, assignee_role):
        
        if not self.user_has_perm(user, 'make_{role}'.format(role=assignee_role)):
            print 'Unauthorized to call assign_role_to_cloak()'
            action = 'assign_role_to_cloak({user}, {assignee_cloak}, {assignee_role})'.format(user=user,
                assignee_cloak=assigne_cloak, assignee_role=assignee_role)
            
            raise UnauthorizedException(user=user,action=action)
        
        
        db_conn = self.main_context['db_conn']
        
        c = db_conn.cursor()
        
        try:
            if not self.cloak_exists(assignee_cloak):
                raise ACLReportError('Not a recognized cloak, \'{cloak}\''.format(cloak=assignee_cloak))
            
            
            if not self.role_exists(assignee_role):
                raise ACLReportError('No such recognized role, \'{role}\''.format(role=assignee_role))
            
            c.execute('''INSERT INTO user_roles (userid,roleid)
                         SELECT users.userid, roles.roleid
                         FROM users, roles
                         WHERE users.cloak=?
                           AND roles.name=?''', (assignee_cloak,assignee_role))
            
            db_conn.commit()
        except:
            #TODO: catch role existing, and send bot error msg
            raise
    
    def user_get_cloaks_with_role(self, user, subject_role):
        if not self.user_has_perm(user, 'whohasrole'):
            action = 'user_get_cloak_roles({user}, {subject_role})'.format(user=user,
                subject_role=subject_role)
            raise UnauthorizedException(user=user,action=action)
        
        if not self.role_exists(subject_role):
            return []
    
        
        db_conn = self.main_context['db_conn']
        c = db_conn.cursor()
        c.execute('''SELECT users.cloak
                     FROM roles, user_roles, users
                     WHERE roles.roleid= user_roles.roleid
                       AND user_roles.userid=users.userid
                       AND roles.name=?''',(subject_role,))
        r = c.fetchall()
        
        return list(map(lambda x: x[0],r))
    
    def user_get_cloak_roles(self, user, subject_cloak):
        
        if not self.user_has_perm(user, 'listroles'):
            
            action = 'user_get_cloak_roles({user}, {subject_cloak})'.format(user=user,
                subject_cloak=subject_cloak)
            raise UnauthorizedException(user=user,action=action)
        
        if not self.cloak_exists(subject_cloak):
            return []
        
        
        db_conn = self.main_context['db_conn']
        c = db_conn.cursor()
        c.execute('''SELECT roles.name
                     FROM roles, user_roles, users
                     WHERE roles.roleid= user_roles.roleid
                       AND user_roles.userid=users.userid
                       AND users.cloak=?''',(subject_cloak,))
        r = c.fetchall()
        
        return list(map(lambda x: x[0],r))
            
    def monitor_privmsg(self, user, channel, msg):
        config = self.config
        
        pass
    def monitor_nick_changes(self,olduser,newuser):
        pass
        
    def monitor_nick_left_channel(self,user,channel):
        pass

class GenericIRCModeCommand(Command):
    def __init__(self,acl,config,permission,cmd,explanation,modes,set_mode,mode_type):
        self.acl = acl
        self.config = config
        
        self.permission = permission
        self.cmd = cmd
        self.explanation = explanation
        self.modes = modes
        self.set_mode = set_mode
        self.mode_type = mode_type

    def run(self,cmd,args,variables):
        user = variables['user']
        
        if not self.acl.user_has_perm(user,self.permission):
            log_message = 'Unauthorized user tried to voice. cmd: {cmd}, args: {args},variables: {variables}'
            log_message = log_message.format(cmd=cmd,args=args,variables=variables)
            
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'You are not authorized to use !{cmd}.'.format(cmd=cmd))
            return
        
        if self.mode_type == 'user_mode':
            for arg_nick in args:
                #filter nicks
                #arg_nick = filter(str.isalnum,arg)
                
                
                if not is_nick(arg_nick):
                    continue
                self.bot.mode(self.bot.factory.channel,set=self.set_mode,modes=self.modes,user=arg_nick)
        elif self.mode_type == 'channel_mode':
            self.bot.mode(self.bot.factory.channel,set=self.set_mode,modes=self.modes)
        else:
            assert False
    def name(self):
        return '!{cmd}'.format(cmd=self.cmd)
    
    def usage(self):
        if self.mode_type == 'user_mode':
            return '!{cmd} <user> [user]*'.format(cmd=self.cmd)
        elif self.mode_type == 'channel_mode':
            return '!{cmd}'.format(cmd=self.cmd)
        else:
            assert False
    def name(self):
        return '{cmd}'.format(cmd=self.cmd)
            
    def user_has_perm(self,user):
        return self.acl.user_has_perm(user,self.permission)

    def explanation(self):
        return self.explanation


class AddUserCloak:
    def __init__(self,acl,cmd):
        self.acl=acl
        self.cmd=cmd
        self.permission='add_user'
    
    def run(self,cmd,args,variables):
        print 'AddUserCloak.run({cmd},{args},{variables})'.format(cmd=cmd,args=args,variables=variables)
        
        user = variables['user']
    
        if not self.acl.user_has_perm(user,self.permission):
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'You are not authorized to use !{cmd}.'.format(cmd=cmd))
    
            return
        
        if len(args) != 1:
            self.bot.print_usage(variables,wrong_usage=True)
            return
        
        arg_cloak = args[0]
        
        self.acl.add_user_cloak(user,arg_cloak)
        
        print 'added user:',arg_cloak
        
        assert self.acl.cloak_exists(arg_cloak)
        self.bot.msg(variables['response_channel'],
                     variables['response_prefix'] + 'Done.')
        
    def name(self):
        return '{cmd}'.format(cmd=self.cmd)
        
    def usage(self):
        return '!{cmd} <cloak>'.format(cmd=self.cmd)
            
    def user_has_perm(self,user):
        return self.acl.user_has_perm(user,self.permission)

    def explanation(self):
        return self.explanation
        
    
class ACLCommand(Command):
    def __init__(self,acl,cmd,permission,priv_cmd=True):
        
        self.acl=acl
        self.cmd=cmd
        self.permission=permission
        self.priv_cmd=priv_cmd
    def user_has_perm(self,user):
        return self.acl.user_has_perm(user,self.permission)
    
    def name(self):
        return '{cmd}'.format(cmd=self.cmd)
            
        
    def run(self,cmd,args,variables):
        user = variables['user']
        
        if not self.acl.user_has_perm(user,self.permission):
            log_message = 'Unauthorized user tried to use ACLCommand. cmd: {cmd}, args: {args},variables: {variables}'
            log_message = log_message.format(cmd=cmd,args=args,variables=variables)
            
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'You are not authorized to use !{cmd}.'.format(cmd=cmd))
            
            return
        
        if self.priv_cmd and variables['in_channel']:
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'This command cannot be used in channel. Private message please.')
            return
            
        
        self.acl_run(cmd,args,variables)

    
class ListUsersOfRole(ACLCommand):
    def __init__(self,acl,cmd):
        ACLCommand.__init__(self,acl,cmd,permission='whohasrole',priv_cmd=True)
    def acl_run(self,cmd,args,variables):
        user = variables['user']
        if len(args) != 1:
            self.bot.print_usage(variables,wrong_usage=True)
            return
        
        arg_role = args[0]
        
        if not self.acl.role_exists(arg_role):
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'No such role, \'{role}\''.format(role=arg_role))
            return
        
        cloaks = self.acl.user_get_cloaks_with_role(user,arg_role)
        
        self.bot.msg(variables['response_channel'],
                     variables['response_prefix'] + '{role}: {cloaks}'.format(role=arg_role,cloaks=str(cloaks)))
    
        
        
        
    def usage(self):
        return '!{cmd} <role>'.format(cmd=self.cmd)
    
    def explanation(self):
        return 'List users with specified role.'
    
class AddUserRole(ACLCommand):
    def __init__(self,acl,cmd):
        ACLCommand.__init__(self,acl,cmd,permission='add_user_role',priv_cmd=True)
        
    def acl_run(self,cmd,args,variables):
        user = variables['user']
        
        if len(args) != 2:
            self.bot.print_usage(variables,wrong_usage=True)
            return
        
        
        arg_cloak = args[0]
        arg_role = args[1]
        
        permission = 'make_{role}'.format(role=arg_role)
        
        if not self.acl.user_has_perm(user, permission):
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'Mmmmm .... no.')
            return
        
        
        if not self.acl.cloak_exists(arg_cloak):
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'User \'{cloak}\' does not exist.'.format(cloak=arg_cloak))
            return
        if not self.acl.role_exists(arg_role):
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'Role \'{role}\' does not exist.'.format(role=arg_role))
            return
        
        self.acl.assign_role_to_cloak(user,arg_cloak,arg_role)
        self.bot.msg(variables['response_channel'],
                     variables['response_prefix'] + 'Done. Role \'{role}\' assigned to \'{cloak}\''.format(role=arg_role,cloak=arg_cloak))
    
    
    def usage(self):
        return '!{cmd} <cloak> <role>'.format(cmd=self.cmd)
    
    def explanation(self):
        return 'Assigns a role to a user\'s cloak.'

class ListRoles(ACLCommand):
    def __init__(self,acl,cmd):
        ACLCommand.__init__(self,acl,cmd,'listroles',True)
    def acl_run(self,cmd,args,variables):
        user = variables['user']
        
        if len(args) != 1:
            self.bot.print_usage(variables,wrong_usage=True)
            return
        
        
        arg_cloak = args[0]
        
        if not self.acl.cloak_exists(arg_cloak):
            self.bot.msg(variables['response_channel'],
                         variables['response_prefix'] + 'Cloak is not recognized.')
            return
            
        
        roles = self.acl.user_get_cloak_roles(user,arg_cloak)
        
        
        response = variables['response_prefix'] + '\'{cloak}\' roles: {roles}'.format(
            cloak=arg_cloak,
            roles=','.join(roles) if len(roles) > 0 else 'None')
        self.bot.msg(variables['response_channel'],response.encode('utf-8'))        
        
    def usage(self):
        return '!{cmd} <cloak>'.format(cmd=self.cmd)

    def explanation(self):
        return 'Lists a user\'s roles'


class PMCommand(ACLCommand):
    def __init__(self,acl,cmd):
        ACLCommand.__init__(self,acl,cmd,'private_message',True)
    
    def acl_run(self,cmd,args,variables):
        
        if not len(args) == 2:
            self.print_usage(variables,wrong_usage=True)
            return
        
        nick = args[0]
        message = args[1]
        
        if nick.lower() == self.bot.nickname.lower():
            self.bot.msg(variables['response_channel'], variables['response_prefix'] + 'Wow, a sense of humor')
            return
            
        self.bot.msg(nick, '{message}'.format(message=args[1]))
        
    def usage(self):
        return '!{cmd} <nick/channel> <message>'.format(cmd=self.cmd)

    def explanation(self):
        return 'PM\s a user/channel on the network with a given message.'

class NoticeCommand(ACLCommand):
    def __init__(self,acl,cmd):
        ACLCommand.__init__(self,acl,cmd,'notice_message',True)
    
    def acl_run(self,cmd,args,variables):
        
        if not len(args) == 2:
            self.print_usage(variables,wrong_usage=True)
            return
        
        nick = args[0]
        message = args[1]
        
        if nick.lower() == self.bot.nickname.lower():
            self.bot.msg(variables['response_channel'], variables['response_prefix'] + 'Wow, a sense of humor')
            return
            
        self.bot.notice(nick, '{message}'.format(message=args[1]))
        
    def usage(self):
        return '!{cmd} <nick/channel> <message>'.format(cmd=self.cmd)

    def explanation(self):
        return 'Sends a notice to a user/channe on the network with a given message.'

        

class KickCommand(ACLCommand):
    def __init__(self,acl,cmd):
        ACLCommand.__init__(self,acl,cmd,'kick',False)
    
    def acl_run(self,cmd,args,variables):
        
        if not (len(args) == 1 or len(args) == 2):
            self.print_usage(variables,wrong_usage=True)
            return
        
        nick = args[0]
        
        if nick.lower() == self.bot.nickname.lower():
            self.bot.msg(variables['response_channel'], variables['response_prefix'] + 'Wow, a sense of humor')
            return
        
        reason = None if len(args) == 1 else args[1]
        
        self.bot.kick(self.bot.factory.channel, nick, reason)
        
    def usage(self):
        return '!{cmd} <nick> [reason]'.format(cmd=self.cmd)

    def explanation(self):
        return 'Kicks a user from the channel.'

class URLMonitor:
    def __init__(self,acl,whitelist):
        self.acl = acl
        self.whitelist = set(whitelist)
    
    FUZZY_URL_RE = tool_utils.URL_RE().url_RE
        
    def monitor_privmsg(self,bot,user,channel,msg,variables):
        if not variables['in_channel']:
            return
        
        result = URLMonitor.FUZZY_URL_RE.search(msg)
        
        if result is None:
            return
        
        url = result.group(0).strip()
        
        
        url = urlparse.urlparse(url)
        print 'url:',url
        if len(url.scheme) == 0:
            url = result.group(0)
            url = 'http://' + url
            url = urlparse.urlparse(url)
        
        path = url.path
        directories = path.split('/')
        
        
        print 'url:',url
        whiteurl = url.netloc
        
        for directory in directories:
            whiteurl += directory
            
            print 'whiteurl:',whiteurl
            if whiteurl in self.whitelist:
                return
            
            whiteurl += '/'
            
            print 'whiteurl:',whiteurl
            
            if whiteurl in self.whitelist:
                return
        
        
        
        
        if url.netloc in self.whitelist:
            return
        
        
        has_cloak = '/' in user
        is_webchat = 'gateway/web/freenode/' in user
        
        print 'has_cloak:',has_cloak
        print 'is_webchat:',is_webchat
        
        if has_cloak and not is_webchat:
            return
        
        
        if self.acl.user_has_perm(user,'trustlinks'):
            return
        
        bot.notice(bot.factory.channel,'1,9Please do not click on links of users if you do not know them.')
        
        
        
        
        
    
def bot_print_usage(variables,wrong_usage=False,self=None):
    user = variables['user']
    usage = ''
    
    
    cmds = []
    usage_list = []
    for cmd_name,cmd_module in self.command_modules.iteritems():
        try:
            if cmd_module.user_has_perm(user):
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


def main():
    

    config_file = open('voice_master_bot_config.yml')

    config = {}

    try:
        config = yaml.load(config_file)
    except:
        print
        print "ERROR: parsing configuration"
        print
        
        raise

    
    main_context = {}
    
    main_context['config'] = config
    
    
    db_conn = sqlite3.connect(config['db_path'])
    main_context['db_conn'] = db_conn
    
    
    c = db_conn.cursor()

    try:
        
        '''permissions (permid, name)'''
        '''roles (roleid, name)'''
        '''users (userid, cloak)'''
        
        '''role_perms (roleid, permid)'''
        '''user_roles (userid, roleid)'''
        
        # Create table
        tables_schemas = [
                  '''CREATE TABLE permissions
                     (permid INTEGER PRIMARY KEY AUTOINCREMENT,
                      name text UNIQUE)''',
                  '''CREATE TABLE roles
                     (roleid INTEGER PRIMARY KEY AUTOINCREMENT,
                      name text UNIQUE)''',
                  '''CREATE TABLE users
                     (userid INTEGER PRIMARY KEY AUTOINCREMENT,
                      cloak text UNIQUE,
                      created_utc integer)''',
                  '''CREATE TABLE role_perms
                     (roleid,
                      permid,
                      UNIQUE(roleid, permid) ON CONFLICT REPLACE)''',
                  '''CREATE TABLE user_roles
                         (userid,
                          roleid,
                          UNIQUE(userid, roleid) ON CONFLICT REPLACE)'''
                          ]
        for table_schema in tables_schemas:
            try:
                c.execute(table_schema)
            except sqlite3.OperationalError as e:
                print 'sqlite3.OperationalError:',e
                print 'table_schema:',table_schema
        
        db_conn.commit()
        
        try:
            c.executemany('''INSERT OR IGNORE INTO roles (name) VALUES (?)''', map(lambda x: (x,), config['default_roles']))
        except sqlite3.OperationalError as e:
            print 'sqlite3.OperationalError:',e
        
        try:
            c.executemany('''INSERT OR IGNORE INTO permissions (name) VALUES (?)''', map(lambda x: (x,), config['default_permissions']))
        except sqlite3.OperationalError as e:
            print 'sqlite3.OperationalError:',e
        
        for role_name,permissions in config['default_role_permissions'].iteritems():
                    
            
            sql = '''INSERT OR IGNORE INTO role_perms (roleid,permid)
                         SELECT roles.roleid, permissions.permid
                         FROM roles, permissions
                         WHERE roles.name=?
                           AND permissions.name=?'''
            c.executemany(sql,zip([role_name]*len(permissions),permissions))
        
        try:
            default_admins = config['default_admins']
            
            sql = '''INSERT OR IGNORE INTO users (cloak) VALUES (?)'''
            
            c.executemany(sql,map(lambda x: (x,),default_admins))
            
            sql = '''INSERT OR IGNORE INTO user_roles (userid,roleid)
                         SELECT users.userid, roles.roleid
                         FROM users, roles
                         WHERE users.cloak=?
                           AND roles.name=?'''
            c.executemany(sql,zip(default_admins,['admin']*len(default_admins)))
            
            
        except sqlite3.OperationalError as e:
            print 'sqlite3.OperationalError:',e
                
        db_conn.commit()
    except sqlite3.OperationalError as e:
        print 'sqlite3.OperationalError:',e
    
    acl = ACL(main_context)
    
    add_user = AddUserCloak(acl,'add_user')
    add_urole = AddUserRole(acl,'add_urole')
    listroles = ListRoles(acl,'listroles')
    whohasrole = ListUsersOfRole(acl,'whohasrole')
    pm = PMCommand(acl,'pm')
    notice = NoticeCommand(acl,'notice')
    kick = KickCommand(acl,'kick')
    
    def on_new_bot(bot):
        
        for command_config in config['channel_mode_commands']:
            command = GenericIRCModeCommand(
                acl,config,
                command_config['permission'],command_config['command'],
                explanation=command_config['explanation'],
                modes=command_config['modes'],
                set_mode=command_config['set'],
                mode_type='channel_mode')
            bot.install_command_module(command.cmd,command)
        for command_config in config['user_mode_commands']:
            command = GenericIRCModeCommand(
                acl,config,
                command_config['permission'],command_config['command'],
                explanation=command_config['explanation'],
                modes=command_config['modes'],
                set_mode=command_config['set'],
                mode_type='user_mode')
            bot.install_command_module(command.cmd,command)
        
        """
        bot.install_command_module(voice_command.cmd,voice_command)
        bot.install_command_module(devoice_command.cmd,devoice_command)
        bot.install_command_module(lockdown_command.cmd,lockdown_command)
        bot.install_command_module(standdown_command.cmd,standdown_command)
        """
        bot.install_command_module(listroles.cmd,listroles)
        bot.install_command_module(add_user.cmd,add_user)
        bot.install_command_module(add_urole.cmd,add_urole)
        bot.install_command_module(whohasrole.cmd,whohasrole)
        
            
        
        bot.install_command_module(pm.cmd, pm)
        bot.install_command_module(notice.cmd, notice)
        bot.install_command_module(kick.cmd, kick)
        bot.install_command_module('help',HelpCommand())
        
        def irc_ERR_CHANOPRIVSNEEDED(prefix,params):
            bot.msg(bot.factory.channel, 'I NEED OPS!')
            pass
        bot.irc_ERR_CHANOPRIVSNEEDED=irc_ERR_CHANOPRIVSNEEDED
        
        bot.print_usage = functools.partial(bot_print_usage, self=bot)
        
        
        def identify_to_nickserv(bot):
            if 'nickserv_password' in config:
                bot.msg('NickServ', 'identify {password}'.format(password=config['nickserv_password']))
            
        bot.signed_on_cbs += [identify_to_nickserv]
        
        """
        def joined_channel(bot,channel):
            if channel == config['channel']:
                bot.msg('ChanServ', 'OP {channel} {nick}'.format(channel=config['channel'], nick=config['nick']))
            
        bot.joined_channel_cbs += [joined_channel]
        """
        
        urlmonitor = URLMonitor(acl,config['urlmonitor']['whitelist'])
        
        bot.privmsg_monitors += [urlmonitor.monitor_privmsg]
        
    
    bot_factory = BotFactory(config['channel'],config['nick'],main_context)
    bot_factory.bot_created_cbs += [on_new_bot]

    reactor.connectTCP(config['server_host'], config['server_port'], bot_factory)
    
    services = [
    
        ]
    
    def run_services():
        if len(bot_factory.bots) == 0:
            return
        for service in services:
            
            try:
                service()
            except Exception as e:
                print 'exception running service:',e,'service:',service
                traceback.print_exc(file=sys.stdout)
    
    lc2 = LoopingCall(run_services)
    
    lc2.start(config['loop_time'])
    
    reactor.run()

    
    
    
    
if __name__ == "__main__":
    main()
