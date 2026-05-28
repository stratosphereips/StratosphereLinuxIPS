// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const box  = require('../lib_widgets/box.js')
const async = require('async')
const color = require('chalk')

class Evidence extends box.BoxClass{

    constructor(grid, redis_database, screen, gridParameters){
        const widgetParameters = {
            top: 'center',
            left: 'center',
            width: '50%',
            height: '50%',
            label:gridParameters[4],
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
        }

        super(grid, gridParameters, widgetParameters)

        this.redis_database = redis_database
        this.screen = screen
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

module.exports = {EvidenceClass: Evidence};
