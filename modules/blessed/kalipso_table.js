      //get the timeline of a selected ip
  var async = require('async')
  var color = require('chalk')
  class Table{
  constructor(grid, blessed, contrib, redis_database,screen, characteristics){
      this.contrib = contrib
      this.screen = screen
      this.blessed = blessed
      this.grid = grid
      this.redis_database = redis_database
      this.widget = this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], this.contrib.table, 
        {keys: true
        , vi:true
        , style:{border:{ fg:'blue'},
      }
        , interactive:characteristics[6]
        , scrollbar: true
        // ,selectedBg:'magenta'
        // , columnSpacing: 5
        , label: characteristics[4]
        , columnWidth: characteristics[5]})}

  setData(ip_tw, timeline_data){
    this.widget.setData({headers:ip_tw, data:timeline_data})
  }
  setDataIPInfo(data){
    this.widget.setData({headers:['asn','geocountry','url','down','ref','com'],data:data})
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

  round(value, decimals) {
  return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
};
  setIPInfo(ip){
    try{ 
      

      this.redis_database.getIpInfo(ip).then(redis_IpInfo_data=>{
        var ipInfo_data  = []
        var ip_info_str = "";
        var ip_info_dict = {'asn':'', 'geocountry':'', 'VirusTotal':{'URL':'', 'down':'','ref':'','com':''}}

        var ipInfo_json = JSON.parse(redis_IpInfo_data);
        var ip_values =  Object.values(ipInfo_json);
        var ip_keys = Object.keys(ipInfo_json);

        if (ipInfo_json.hasOwnProperty('VirusTotal')){
          ip_info_dict['VirusTotal']['URL'] = this.round(ipInfo_json['VirusTotal']['URL'],5)
          ip_info_dict['VirusTotal']['down'] = this.round(ipInfo_json['VirusTotal']['down'],5)
          ip_info_dict['VirusTotal']['ref'] = this.round(ipInfo_json['VirusTotal']['ref'],5)
          ip_info_dict['VirusTotal']['com'] = this.round(ipInfo_json['VirusTotal']['com'],5)
        }
        if(ipInfo_json.hasOwnProperty('asn')){
          ip_info_dict['asn'] = ipInfo_json['asn']
        }
        if(ipInfo_json.hasOwnProperty('geocountry')){
          ip_info_dict['geocountry'] = ipInfo_json['geocountry']
        }
        ipInfo_data.push([ip_info_dict['asn'], ip_info_dict['geocountry'], ip_info_dict['VirusTotal']['URL'], ip_info_dict['VirusTotal']['down'],ip_info_dict['VirusTotal']['ref'],ip_info_dict['VirusTotal']['com']])
        this.setDataIPInfo(ipInfo_data)
        this.screen.render()
  })
    }
    catch (err){
      console.log(err)
    }
  }


  setTimeline(ip, timewindow){
    try{
    this.redis_database.getTimeline(ip, timewindow).then(redis_timeline_data=>{
      var timeline_data = [];
      if(redis_timeline_data.length < 1){this.setData([ip+" "+timewindow], timeline_data);}
      else{
        async.each(redis_timeline_data, (timeline, callback)=>{
          var row = [];
          var timeline_json = JSON.parse(timeline)

          var pink_keywords = ['Query','Answers','SN', 'Trusted', 'Resumed', 'Version']
          var red_keywords = ['critical warning' ]
          var orange_keywords = ['Sent','Recv','Tot','Size','Type']
          var blue_keywords = ['dport_name', 'dport_name/proto']
          var cyan_keywords = ['daddr', 'saddr']
          var light_pink_keywords = ['dns_resolution']

          // split the timeline on parts
          if(timeline_json['timestamp']){

          var final_timeline = ''

          for (let [key, value] of Object.entries(timeline_json)) {
            if(key.includes('critical warning')){
              value = color.red(value)
            }
            else if(key.includes('warning')){
              value = color.rgb(255,165,0)(value)
            }
            else if(key.includes('timestamp')){
              value = value.substring(0, value.indexOf('.'));
            }
            else if(key.includes('dport/proto')){
              value = color.bold.yellow(value)
            }
            else if(key.includes('info')){
              value = color.rgb(105,105,105)(value)
            }
            else if (blue_keywords.some(element => key.includes(element))){
              value = color.rgb(51, 153, 255)(value);
            }
            else if(cyan_keywords.some(element => key.includes(element))){
              value = color.rgb(112, 168, 154)('[' + value+']')
            }
            else if (orange_keywords.some(element => key.includes(element))){
              value =key + ':' + color.rgb(255, 153, 51)(value);
            }
            else if (red_keywords .some(element => key.includes(element))){
              value = color.red(value);
            }
            else if (light_pink_keywords.some(element => key.includes(element))){
              value = color.rgb(255,182,193)(value) ;
            }
            else if (pink_keywords .some(element => key.includes(element))){
              value = key + ':'+color.rgb(219,112,147)(value);
            }
            if(value){
              final_timeline += value +' ';}}
              row.push(final_timeline);
              timeline_data.push(row);
          }
          else{
            var final_timeline = ''

            for (let [key, value] of Object.entries(timeline_json)) {
              row = []
              final_timeline = key.padStart(21+key.length) +': ' +color.rgb(51, 153, 255)(value);
              row.push(final_timeline);
              timeline_data.push(row);
            }
        }
        callback();
      },(err)=>{
        if(err) {console.log(err);} 
        else{
          this.setData([ip+" "+timewindow], timeline_data);
          this.screen.render()}
        });
      }
    })}
    catch(err){console.log(err)}}
  
  }

module.exports = Table;