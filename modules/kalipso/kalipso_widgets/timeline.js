// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib, async, color, stripAnsi } = require("./libraries.js");
const table = require("../lib_widgets/table.js")

class Timeline extends table.TableClass{

    constructor(grid, screen, redis_database, characteristics){
        const widgetParameters = {
          keys: true
        , vi:true
        , style:{border:{ fg:'blue'}}
        , interactive:characteristics[6]
        , scrollbar: true
        , label: characteristics[4]
        , columnWidth: characteristics[5]
        }
        super(grid, characteristics, widgetParameters)
        this.screen = screen
        this.redis_database = redis_database
    }

    capitalizeFirstLetter(data){
        return data.charAt(0).toUpperCase() + data.slice(1);
    }


    timeConverter(UNIX_timestamp){
        let a = new Date(UNIX_timestamp * 1000);
        let months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        let year = a.getFullYear();
        let month = a.getMonth() + 1 < 10 ? '0' + (a.getMonth() + 1) : (a.getMonth() + 1) ;
        let date = a.getDate() < 10 ? '0' + a.getDate() : a.getDate() ;
        let hour =  a.getHours() < 10 ? '0' + a.getHours() : a.getHours() ;
        let min =  a.getMinutes() < 10 ? '0' + a.getMinutes() : a.getMinutes();
        let sec = a.getSeconds() < 10 ? '0' + a.getSeconds() : a.getSeconds() ;
        //  let time = date + ' ' + month + ' ' + year + ' ' + hour + ':' + min + ':' + sec ;
        let time = year + '/' + month  + '/' + date + ' ' + hour + ':' + min + ':' + sec;
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
              let timeline_line = stripAnsi(item.content)
              let ip = timeline_line.substring(
              timeline_line.lastIndexOf("[") + 1,
              timeline_line.lastIndexOf("]")
              )
              if(ip && !ip.includes("'")){
                ip_info_widget.setIPInfo(ip)}
              }
            catch(err){console.log('Error in the function on() in kalipso_table.js. Error: ')}
        })
    }

    /*Set timeline data in the widget "Table".*/
    setTimeline(ip, timewindow){
        try{
            // get the timeline of thi ip and tw from the db for example "profile_ip_timewindow_timeline"
            this.redis_database.getTimeline(ip, timewindow).then(redis_timeline_data=>{
            let timeline_data = [];
            // handle no timeline data found
            if(redis_timeline_data.length < 1){this.setData([ip+" "+timewindow], timeline_data); this.screen.render();}
            else{
                // found timeline data, parse it
                redis_timeline_data.forEach((timeline)=>{
                    let row = [];
                    let timeline_json = JSON.parse(timeline)
                    // this one is coming from database.py: get_dns_resolution
                    let pink_keywords_parameter = ['dns_resolution']
                    let red_keywords = ['critical warning' ]
                    let orange_keywords = ['sent','recv','tot','size','type','duration']
                    let blue_keywords = ['dport_name', 'dport_name/proto']
                    let cyan_keywords = []

                    // display ip (source or dst) based on the direction
                    let direction = timeline_json['preposition'];
                    if (direction === "to" ){
                        cyan_keywords.push('daddr')
                        timeline_json['saddr'] = ''

                    } else if(direction === "from"){
                        cyan_keywords.push('saddr')
                        timeline_json['daddr'] = ''
                    }

                      //  we will be appending each row value to this final_timeline
                       // each value has it's own color
                      let final_timeline = ''
                      let info = ''

                      for (let [key, value] of Object.entries(timeline_json)) {
                        let flow_value = ''

                        if(key.includes('critical warning')){
                          flow_value = color.red(value)
                        }
                        else if(key.includes('warning')){
                          flow_value = color.rgb(255,165,0)(value)
                        }
                        else if(key.includes('timestamp')){
                          flow_value = color.bold(value);
                        }
                        else if(key.includes('dport/proto')){
                          flow_value = color.bold.yellow(value)
                        }
                        else if(key.includes('info')){
                            info = value
                        }
                        else if (blue_keywords.some(element => key.includes(element))){
                          flow_value = color.rgb(51, 153, 255)(value);
                        }
                        else if(cyan_keywords.some(element => key.includes(element))){
                          flow_value = color.rgb(112, 168, 154)('[' + value+']')
                        }
                        else if (orange_keywords.some(element => key.includes(element))){
                          flow_value = this.capitalizeFirstLetter(key) + ':' + color.rgb(255, 153, 51)(value);
                        }
                        else if (red_keywords .some(element => key.includes(element))){
                          flow_value = color.red(value);
                        }
                        else if (pink_keywords_parameter .some(element => key.includes(element))){
                          flow_value = color.rgb(219,112,147)(value);
                        }

                        if(flow_value){
                          final_timeline += flow_value +' ';}
                        }

                        row.push(final_timeline);
                        timeline_data.push(row);
                        if(info){
                            for (let [key, value] of Object.entries(info)) {
                                row = []
                                let info_format = color.bold(this.capitalizeFirstLetter(key).padStart(20 + key.length)) + ':' + color.rgb(219,112,147)(value) + ' ';
                                row.push(info_format);
                                timeline_data.push(row);
                            }
                        }
                })

              this.redis_database.getStarttimeForTW(ip,timewindow).then(timewindow_starttime=>{
                  this.setData([ip+" "+timewindow + " " + this.timeConverter(timewindow_starttime)], timeline_data);
                  this.screen.render();
              })
              }
            })
        }
        catch(err){console.log("Error in setTimeline() in kalipso_table.js. Error: ",err)}
  }
}

module.exports = {TimelineClass: Timeline};
