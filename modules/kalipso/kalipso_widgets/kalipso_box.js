var async = require('async')
var color = require('chalk')

class Box{
  constructor(grid, blessed, contrib, redis_database,screen, characteristics){
      this.contrib = contrib
      this.screen = screen
      this.blessed = blessed
      this.grid = grid
      this.redis_database = redis_database
      this.widget = this.initBox(characteristics);
}
  initBox(characteristics){
    return this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], this.blessed.box,{
        top: 'center', 
        left: 'center',
        width: '50%',
        height: '50%',
        label:characteristics[4],
        tags: true,
        keys: true,
        style:{
          border:{ fg:'blue',type: 'line'},
          focus: {border:{ fg:'magenta'}
      }},
        vi:true,
        scrollable: true,
        alwaysScroll: true,
        
        scrollbar: {
          ch: ' ',
          inverse: true
        }
    })
  }
  setData(data){
    this.widget.setContent(data)
      }
  hide(){
    this.widget.hide()
      }
  show(){
    this.widget.show()
      }
  focus(){
    this.widget.focus()
      }
  setEvidence(ip, timewindow){
    try{
      var evidence_data = ''
      this.redis_database.getEvidence(ip, timewindow).then(redis_evidence_data=>{
        if (redis_evidence_data==null){
          return this.setData(evidence_data)
        }
        var evidence_json = JSON.parse(redis_evidence_data);
        var evidence_keys = Object.keys(evidence_json); 
        async.each(evidence_keys, (key,callback)=>{
          var key_dict = JSON.parse(key)
          var key_values = Object.values(key_dict).join(':')
          if ((key_dict['type_evidence'] == 'ThreatIntelligenceBlacklistIP') || (key_dict['type_evidence'] == 'ThreatIntelligenceBlacklistDomain')){
            evidence_data = '{bold}'+color.green('Detected '+key_dict['type_detection']+ ' ' +key_dict['detection_info'])+'{/bold}'+". Blacklisted in "+evidence_json[key]["description"]+'\n'

          }
          else{
          evidence_data = '{bold}'+color.green('Detected '+key_dict['type_detection']+ ' ' +key_dict['detection_info'])+'{/bold}'+". "+evidence_json[key]["description"]+'\n'
          }
          callback();
          }, (err)=>{
            if(err){console.log(err)}
            else{return this.setData(evidence_data)}
        });
        });
    }
    catch (err){
      console.log(err)
    }
  }
}
    module.exports = Box;