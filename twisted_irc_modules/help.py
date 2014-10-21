

from command import Command

class HelpCommand(Command):
    
    def run(self,cmd,args,variables):
        
        self.bot.print_usage(variables,wrong_usage=False)

    def name(self):
        return 'help'

    def usage(self):
        return '!help'

    def explanation(self):
        return 'You have to know what this does.'
    
    def user_has_perm(self,user):
        return True

