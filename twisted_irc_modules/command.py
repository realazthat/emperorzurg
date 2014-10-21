
    
class Command:
    def __init__(self):
        pass
    
    def run(self,cmd,args,variables):
        raise Exception('Implement this')

    def name(self):
        raise Exception('Implement this')
    
    def usage(self):
        raise Exception('Implement this')
    
    def explanation(self):
        raise Exception('Implement this')
    
    def user_has_perm(self,user):
        raise Exception('Implement this')
