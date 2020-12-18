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
        , style:{border:{ fg:'blue'},
            }
        , interactive:characteristics[6]
        , scrollbar: true
        , label: characteristics[4]
        , columnWidth: characteristics[5]
        }
      )
  }

  setData(ip_tw, timeline_data){
    /*
    To set data in the widget
    */
    this.widget.setData({headers:ip_tw, data:timeline_data})
  }


  hide(){
    /*
    To hide the widget
    */
    this.widget.hide()
  }
  show(){
    /*
    To show the widget
    */
    this.widget.show()
  }
  focus(){
    /*
    To focus on widget
    */
    this.widget.focus()
  }

  round(value, decimals) {
    /*
    Round the number to specific number of decimals
    */
    return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
  }

  on(ip_info_widget){
    /*
    Function to set ip info of the ip in the timeline to the ip info table
    */
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
    catch(err){}
    })
  }

  setTimeline(ip, timewindow){
    /*
    Fill timeline data in the widget with appropriate color.
    */
    try{
      this.redis_database.getTimeline(ip, timewindow).then(redis_timeline_data=>{
        var timeline_data = [];
        if(redis_timeline_data.length < 1){this.setData([ip+" "+timewindow], timeline_data);}
        else{
          async.each(redis_timeline_data, (timeline, callback)=>{
            var row = [];
            var timeline_json = JSON.parse(timeline)

			var pink_keywords = ['Query','Answers','SN', 'Trusted', 'Resumed', 'Version']
			var pink_keywords_parameter = ['dns_resolution']
            var red_keywords = ['critical warning' ]
            var orange_keywords = ['Sent','Recv','Tot','Size','Type']
            var blue_keywords = ['dport_name', 'dport_name/proto']
            var cyan_keywords = ['daddr', 'saddr']

            if(timeline_json['timestamp']){
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
                  final_timeline += value +' ';}}
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
            }}


          callback();
          },(err)=>{
            if(err) {console.log(err);} 
            else{
              this.setData([ip+" "+timewindow], timeline_data);
              this.screen.render()}
          });
        }
      })
    }
    catch(err){console.log(err)}
  }
  
}

module.exports = Table;
