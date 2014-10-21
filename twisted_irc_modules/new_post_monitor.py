
class NewPostMonitor:
    
    def __init__(self,config):
        self.before = None
        self.config = config
        self.new_post_cbs = []
        
        
    
    def run(self):
        config = self.config
        
        
        
        client = requests.session()
        
        try:
            parameters={}
            
            if self.before is not None:
                parameters['before'] = self.before
                parameters['limit'] = 5
            else:
                parameters['limit'] = 1
            
            
            url = r'http://www.reddit.com/r/{sr}/{top}.json'.format(sr=config['subreddit'],top='new')
            
            headers = {'User-agent': config['user-agent']}
            print 'url:',url
            r = client.get(url,params=parameters)
            j = json.loads(r.text)
        
            def set_before():
                if len(j['data']['children']) != 0:
                    first_post_kind = j['data']['children'][0]['kind']
                    first_post_id = j['data']['children'][0]['data']['id']
                
                    self.before = '{kind}_{post_id}'.format(kind=first_post_kind,post_id=first_post_id)
            
            if self.before is None:
                set_before()
                return
            
            
            set_before()
            
            #print 'self.before:',self.before
            
            for new_post in j['data']['children']:
                
                for cb in self.new_post_cbs:
                    
                    try:
                        cb(new_post)
                    except Exception as e:
                        print 'Exception during new_post_cb():',e
                        traceback.print_exc(file=sys.stdout)
            
        finally:
            client.close()

