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

    /*Initialize the parameters for the widgets 'Box'.*/
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
              focus: {border:{ fg:'magenta'}}
            },
            vi:true,
            scrollable: true,
            alwaysScroll: true,
            scrollbar: {
              ch: ' ',
              inverse: true
            }
        })
    }

    /*Set data in the widget*/
    setData(data){
        this.widget.setContent(data)
    }

    /*Hide the widget from the screen*/
    hide(){
        this.widget.hide()
    }

    /*Show the widget on the screen*/
    show(){
        this.widget.show()
    }

    /*Focus on the widget in the screen*/
    focus(){
        this.widget.focus()
    }

    /*Widget 'Box' is used to display the evidences in the main screen of Kalipso.
      This function generate the evidence data to be put in the box.
      It retrieves the data from the Redis database and put it in the necessary format for the widget.
      */
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
                    var evidence_details =  JSON.parse(evidence_json[key])
                    // var key_dict = JSON.parse(key)
                    // var key_values = Object.values(key_dict).join(':')
                    if ((evidence_details['type_evidence'] == 'ThreatIntelligenceBlacklistIP')
                        || (evidence_details['type_evidence'] == 'ThreatIntelligenceBlacklistDomain'))
                    {
                        evidence_data =
                        evidence_data +
                            '{bold}' +
                            color.green('Detected '+evidence_details['type_detection'] + ' ' + evidence_details['detection_info']) +
                            '{/bold}' +
                            ". Blacklisted in " + evidence_details["description"] + '\n'
                        // evidence_data = evidence_data + '{bold}' + key + '\n'
                    }

                  else{
                    evidence_data = evidence_data +
                        '{bold}'+
                        color.green('Detected '+evidence_details['type_detection'] + ' ' +evidence_details['detection_info']) +
                        '{/bold}' +
                        ". " + evidence_details["description"] + '\n'
                  }

                  callback();
                  }, (err)=>{
                    if(err){console.log('Error to iterate through the evidences in the timewindow, check setEvidence() in kalipso_box.js. Error: ', err)}
                    else{
                    return this.setData(evidence_data)}
                  }
                );
            });
        }

        catch (err){
            console.log('Error in the setEvidence() in kalipso_box.js: ' ,err)
        }
    }
}

module.exports = Box;