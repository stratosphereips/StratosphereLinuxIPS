// const redis = require('redis')
class WidgetTree{
    constructor({blessed = {}, contrib = {}, screen = {}, grid = {},redis = {}}){
        this.blessed = blessed;
        this.contrib = contrib;
        this.screen = screen;
        this.grid = grid;
        this.parameters = { vi:true, style: {border: {fg:'magenta'}}, template: { lines: true }, label: 'default'};
        this.widget = this.getWidget();
        this.redis = redis;
        
    }

    getWidget(){
        return this.grid.gridObj.set(...this.grid.gridLayout, this.contrib.tree, this.parameters);
    }


    setTree(){
        var ips_with_timewindows = {};
        var redis_tree = this.redis.createClient();
        function setTreeData(ip_timewindow_dict){
          /*
          sets ips and their tws for the tree.
          */
          var ips = Object.keys(ip_timewindow_dict);
          var explorer = {extended: true
          , children: function(self){
              var result = {};
              try {
                if (!self.childrenContent) {
                  for(i=0;i<ips.length;i++){
                    var tw = ip_timewindow_dict[ips[i]]
                    child = ips[i];
                    result[child] = { name: child, extended:false, children: tw[0]};
                    }
                }else
                result = self.childrenContent;
              } catch (e){}
              return result;
            }
        }
        return explorer;};

        function getTreeData(key){
            if(key.includes('timeline')){
                var key_list = key.split('_');
                var l  = {}
                l[key_list[2]]={};
                if(!Object.keys(ips_with_timewindows).includes(key_list[1])){
                ips_with_timewindows[key_list[1]]  = [];
                ips_with_timewindows[key_list[1]].push(l);}
                else{
                    ips_with_timewindows[key_list[1]].push(l);
                }
            }
        }
        function timewindows_promises(reply) {
            return Promise.all(reply.map( key_redis => getTreeData(key_redis))).then(this.widget.setData(setTreeData(ips_with_timewindows))); //this.widget.setData(setTreeData(ips_with_timewindows))
        }

        redis_tree.keys('*', (err,reply)=>{
            timewindows_promises(reply)
        })
    
        
        
    }

    
}
module.exports = WidgetTree;
