
import traceback,sys, requests,json

class NewCommentMonitor:
    
    def __init__(self,config):
        self.config = config
        self.new_comment_cbs = []
        self.before = None

    def run(self):
        config = self.config
        
        
        parameters = {}
        
        if self.before is not None:
            parameters['before'] = self.before
            parameters['limit'] = config['reddit_comment_limit_per_query']
        else:
            parameters['limit'] = 1
        
        headers = {'User-agent': config['user-agent']}
        
        r = requests.get('http://www.reddit.com/r/{sr}/comments.json'.format(sr=config['subreddit']),
                         headers=headers,
                         params=parameters)

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
        
        for comment in j['data']['children']:
            
            try:
                for cb in self.new_comment_cbs:
                    try:
                        cb(comment)
                    except Exception as e:
                        print 'exception during comment callback handling:',e
                        traceback.print_exc(file=sys.stdout)
                        continue
                    
            except Exception as e:
                print 'exception during comment handling:',e
                traceback.print_exc(file=sys.stdout)
                continue
        
        


