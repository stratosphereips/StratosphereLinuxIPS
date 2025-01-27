// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib, async } = require("./libraries.js");
const listTable = require("../lib_widgets/listtable.js")

class InTuples extends listTable.ListTableClass{

    constructor(grid, redis_database,screen, characteristics, limit_letter_intuple){
        super(grid, redis_database, characteristics)
                this.screen = screen
                this.limit_letter_intuple = limit_letter_intuple
    }

    /*Combine data for InTuples*/
    setInTuples(ip, timewindow){
        try{

            this.redis_database.getInTuples(ip, timewindow).then(redis_inTuples=>{
            var data = [['key','string','dns_resolution','SNI','RDNS','asn','geo','url','down','ref','com']]
            if(redis_inTuples==null){this.setData(data);this.screen.render(); return;}
            var json_inTuples = JSON.parse(redis_inTuples)
            var keys = Object.keys(json_inTuples)
            async.each(keys,(key, callback)=>{
                let tuple_info = json_inTuples[key];
                let split_tuple = key.split('-')
                let inTuple_ip = split_tuple[0]
                let inTuple_port = split_tuple[1]
                let inTuple_protocol = split_tuple[2]
                var letters_string = tuple_info[0].substr(0, this.limit_letter_intuple)
                this.getIPInfo_dict(inTuple_ip).then(ip_info_dict =>{
                this.redis_database.getDNSResolution(inTuple_ip).then(dns_resolution=>{
                var letter_string_chunks = this.chunkString(letters_string.trim(),40);
                var length_letter = letter_string_chunks.length
                if(dns_resolution){dns_resolution = JSON.parse(dns_resolution)}
                var length_dns_resolution = dns_resolution.length
                var all_sni = ip_info_dict['SNI']
                var sni = all_sni.slice(Math.max(all_sni.length - 3, 0))
                var length_sni = sni.length
                var max_length = Math.max(length_dns_resolution, length_letter, length_sni)
                var indexes_array = Array.from(Array(max_length).keys())

             async.forEach(indexes_array, (ind, callback)=>{
                var row = [];
                var temp_dns_resolution = ''
                var temp_str =''
                var temp_sni ='';

                if(dns_resolution[ind] != undefined){temp_dns_resolution = dns_resolution[ind]};

                if(sni[ind] != undefined &&
                    inTuple_port.localeCompare(sni[ind]["dport"]) ==0 &&
                    inTuple_protocol.localeCompare("tcp") == 0){
                    temp_sni = sni[ind]["server_name"];}

                if(letter_string_chunks[ind] != undefined){temp_str = letter_string_chunks[ind]}

                if(ind ==0){
                    row.push(key, temp_str, temp_dns_resolution,
                              temp_sni,ip_info_dict['reverse_dns'], ip_info_dict['asn'].slice(0,20), ip_info_dict['geo'],
                              ip_info_dict['url'], ip_info_dict['down'], ip_info_dict['ref'],
                              ip_info_dict['com'])}
                else{
                    row.push('', temp_str, temp_dns_resolution,
                              temp_sni, '','','','','','','')}
                data.push(row)
                callback(null)
                }, (err)=>{if(err){console.log('Error in setInTuples in kalipso_listtable.js. Error:', err);}})
                callback(null)
                })})
             },(err)=>{if(err){console.log('Error in setInTuples in kalipso_listtable.js. Error:',err)}
                    else{
                      this.setData(data);
                      this.screen.render()}}
          )
          })
        }
                catch(err){
            console.log('Check setInTuples in kalipso_listtable.js. Error: ', err)
            reject(err)
        }

  }
}

module.exports = {InTuplesClass:InTuples}
