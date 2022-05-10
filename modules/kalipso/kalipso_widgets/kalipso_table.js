var async = require('async')
var color = require('chalk')
var stripAnsi = require('strip-ansi')

class Table{

    constructor(grid, blessed, contrib, redis_database,screen, characteristics){
        this.contrib = contrib
        this.screen = screen
        this.blessed = blessed
        this.grid = grid
        this.redis_database = redis_database
        this.widget = this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], this.contrib.table,
        {
          keys: true
        , vi:true
        , style:{border:{ fg:'blue'}}
        , interactive:characteristics[6]
        , scrollbar: true
        , label: characteristics[4]
        , columnWidth: characteristics[5]
        }
        )
    }

    /*Set data in the widget 'Table'*/
    setData(widget_headers, widget_data){
        this.widget.setData({headers:widget_headers, data:widget_data})
    }

    /*Hide the widget on the screen*/
    hide(){
        this.widget.hide()
    }

    /*Show the widget on the screen*/
    show(){
        this.widget.show()
    }

    /*Focus on the widget on the screen*/
    focus(){
        this.widget.focus()
    }



    timeConverter(UNIX_timestamp){
        var a = new Date(UNIX_timestamp * 1000);
        var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        var year = a.getFullYear();
        var month = a.getMonth() + 1 < 10 ? '0' + (a.getMonth() + 1) : (a.getMonth() + 1) ;
        var date = a.getDate() < 10 ? '0' + a.getDate() : a.getDate() ;
        var hour =  a.getHours() < 10 ? '0' + a.getHours() : a.getHours() ;
        var min =  a.getMinutes() < 10 ? '0' + a.getMinutes() : a.getMinutes();
        var sec = a.getSeconds() < 10 ? '0' + a.getSeconds() : a.getSeconds() ;
        //  var time = date + ' ' + month + ' ' + year + ' ' + hour + ':' + min + ':' + sec ;
        var time = year + '/' + month  + '/' + date + ' ' + hour + ':' + min + ':' + sec;
        return time;
    }

    /*Round the number to specific number of decimals*/
    round(value, decimals) {
    return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
    }

    /*Set IP info of the IP selected in the timeline to the widget 'Table'*/
    on(ip_info_widget){
        this.widget.rows.on('select', (item, index) => {
            try{
              var timeline_line = stripAnsi(item.content)
              var ip = timeline_line.substring(
              timeline_line.lastIndexOf("[") + 1,
              timeline_line.lastIndexOf("]")
              )
              if(ip && !ip.includes("'")){
                ip_info_widget.setIPInfo(ip)}
              }
            catch(err){console.log('Error in the function on() in kalipso_table.js. Error: ')}
        })
    }

    /*Set evidence for all the timewindows in profile.*/
    setEvidencesInProfile(ip){
        try{
            this.widget.setLabel('profile_'+ip+' Evidences')
            this.redis_database.getAllProfileEvidences(ip).then(all_profile_evidences=>{
                var evidence_data = [];
                if(all_profile_evidences==null){this.setData(['twid','evidences'], evidence_data); this.screen.render()}
                else{
                    var temp_dict = Object.keys(all_profile_evidences)
                    temp_dict.sort(function(a,b){return(Number(a.match(/(\d+)/g)[0]) - Number((b.match(/(\d+)/g)[0])))});

                    async.forEach(temp_dict,(twid, callback)=>{
                    var tw_evidences_json = JSON.parse(all_profile_evidences[twid]);
                        async.forEachOf(Object.entries(tw_evidences_json),([key, evidence], index)=>{
                            var row = []
                            if(index==0){row.push(twid)}
                            else{row.push('')}

                            var key_dict = JSON.parse(key)
                            var key_values = Object.values(key_dict).join(':')
                            var evidence_final = '{bold}'+color.green(key_values)+'{/bold}'+" "+evidence["description"]+'\n'

                            row.push(evidence_final);
                            evidence_data.push(row)
                        })
                    callback()
                    },(err)=>{
                        if(err){console.log('Cannot set evidence in "z" hotkey, check setEvidenceInProfile() in kalipso_table.js. Error: ',err)}
                        else{
                            this.setData(['timewindow','evidence'],evidence_data);
                            this.screen.render();
                        }
                    });
                }
            })
        }
        catch(err){console.log('Check setEvidenceInProfile() in kalipso_table.js. Error: ',err)}
    }

    /*Set timeline data in the widget "Table".*/
    setTimeline(ip, timewindow){
        try{
            // get the timeline of thi ip and tw from the db for example "profile_ip_timewindow_timeline"
            this.redis_database.getTimeline(ip, timewindow).then(redis_timeline_data=>{
            var timeline_data = [];
            // handle no timeline data found
            if(redis_timeline_data.length < 1){this.setData([ip+" "+timewindow], timeline_data);}
            else{
                // found timeline data, parse it
                async.each(redis_timeline_data, (timeline, callback)=>{
                    var row = [];
                    var timeline_json = JSON.parse(timeline)
                    var pink_keywords = ['Query','Answers','SN', 'Trusted', 'Resumed', 'Version', 'Login', 'Auth attempts','Server','Client']
                    // this one is coming from database.py: get_dns_resolution
                    var pink_keywords_parameter = ['dns_resolution']
                    var red_keywords = ['critical warning' ]
                    var orange_keywords = ['Sent','Recv','Tot','Size','Type','Duration']
                    var blue_keywords = ['dport_name', 'dport_name/proto']
                    var cyan_keywords = ['daddr', 'saddr']

                    if(timeline_json['timestamp']){
                      //  we will be appending each row value to thiss final_timeline
                        // each value has it's own color
                      var final_timeline = ''
                      var http_data = ''

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
                        else if (pink_keywords_parameter .some(element => key.includes(element))){
                          value = color.rgb(219,112,147)(value);
                        }
                        else if (pink_keywords .some(element => key.includes(element))){
                          value = key + ':'+color.rgb(219,112,147)(value);
                        }
                        else if(key.includes('http_data')){
                          http_data = value;
                        }
                        if(value && !http_data){
                          final_timeline += value +' ';}
                        }

                        row.push(final_timeline);
                        timeline_data.push(row);
                        if(http_data){
                            var http_timeline = ''

                            for (let [key, value] of Object.entries(http_data)) {
                                row = []
                                http_timeline = key.padStart(21+key.length) +': ' +color.rgb(51, 153, 255)(value);
                                row.push(http_timeline);
                                timeline_data.push(row);
                            }
                        }
                    }

              callback();
              },(err)=>{
                if(err) {console.log('Error in setTimeline() in kalipso_table.js. Error: ',err);}
                else{
                  this.redis_database.getStarttimeForTW(ip,timewindow).then(timewindow_starttime=>{
                      this.setData([ip+" "+timewindow + " " + this.timeConverter(timewindow_starttime)], timeline_data);
                      this.screen.render()

                  })
                  }
              });
            }
        })
    }
    catch(err){console.log("Error in setTimeline() in kalipso_table.js. Error: ",err)}
  }
  
}

module.exports = Table;
