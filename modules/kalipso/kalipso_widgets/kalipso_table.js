const { redis, blessed, blessed_contrib } = require("./libraries.js");

var async = require('async')
var color = require('chalk')
var stripAnsi = require('strip-ansi')

class Table{

    constructor(grid, redis_database,screen, characteristics){
        this.screen = screen
        this.grid = grid
        this.redis_database = redis_database
        this.widget = this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], blessed_contrib.table,
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
                            var evidence_dict = JSON.parse(evidence)
                            var evidence_final = evidence_dict["description"]+'\n'

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

}

module.exports = {TableClass: Table};
