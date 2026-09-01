// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib, async } = require("./libraries.js");
const table = require("../lib_widgets/table.js")

class ProfileEvidences extends table.TableClass{

    constructor(grid, redis_database,screen, characteristics){
    const widgetParameters =         {
          keys: true
        , vi:true
        , style:{border:{ fg:'blue'}}
        , interactive:characteristics[6]
        , scrollbar: true
        , label: characteristics[4]
        , columnWidth: characteristics[5]
        }
        super(grid, characteristics, widgetParameters)
        this.redis_database = redis_database
        this.screen = screen
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



module.exports = {ProfileEvidencesClass: ProfileEvidences};
