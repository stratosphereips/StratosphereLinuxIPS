// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
var fs = require('fs')
const { redis, blessed, blessed_contrib, async } = require("../kalipso_widgets/libraries.js");

class ListTable{
    constructor(grid,  redis_database, characteristics, limit_letter_outtuple=0){
        this.grid = grid
        this.redis_database = redis_database
        this.widget = this.initListTable(characteristics);
        this.limit_letter_outtuple = limit_letter_outtuple
        this.country_code = {}
        this.read_file().then(data=>{this.country_code = data})
}
    /*Initialise the widget ListTable and its parameters*/
    initListTable(characteristics){
        return this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], blessed.listtable, {
          keys: true,
          mouse: true,
          vi:true,
          tags: true,
          border: 'line',
          style: {
            header: {
              fg: 'blue',
              bold: true
            },
            cell: {
              selected: {
                bg: 'magenta'
              }
            }
          },
          align: 'left'
        })
    }

    /*Set data in the widget ListTable*/
    setData(data){
        this.widget.setData(data)
    }

    /*Read the file with countries and there shortenings.*/
    read_file(){
        let code = {}
        return new Promise((resolve, reject)=>{ fs.readFile('countries.json', 'utf8', (err,data)=>{
            if(err){console.log('Check read_file() in kalipso_listtable.js. Error: ', err); reject(err);}
            else{resolve(JSON.parse(data))}
        })})
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

    /*Round the numbers by specific decimals*/
    round(value, decimals) {
        return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
    }

    /*Function to split the string in several lines.*/
    chunkString(str, len) {
        const size = Math.ceil(str.length/len)
        const r = Array(size)
        let offset = 0

        for (let i = 0; i < size; i++) {
          r[i] = str.substr(offset, len)
          offset += len
        }
        return r
    }
   /*Set information about the selected IP in the timeline.*/
   setIPInfo(ip){
    try{
        this.getIPInfo_dict(ip).then(ip_info_dict =>{
            // fill the widget at the top right of the screen
            var ipInfo_data  = [['asn','geo','url','down','ref','com']]
            this.widget.setLabel(ip_info_dict['reverse_dns'])
            ipInfo_data.push([ip_info_dict['asn'], ip_info_dict['geo'], ip_info_dict['url'], ip_info_dict['down'],ip_info_dict['ref'],ip_info_dict['com']])
            this.setData(ipInfo_data)
        })
    }
        catch (err){
        console.log('Check setIPInfo in kalipso_listtable.js. Error: ',err)}
  }


    getIPInfo_dict(ip){
        return new Promise ((resolve, reject)=>{this.redis_database.getIpInfo(ip).then(redis_IpInfo_data=>{
        try{
            var ip_info_dict = {'asn':'', 'geo':'', 'SNI':'', 'reverse_dns':'', 'url':'', 'down':'','ref':'','com':''}
            if(redis_IpInfo_data==null){resolve(ip_info_dict)}
            else{
                var ipInfo_json = JSON.parse(redis_IpInfo_data);

                if (ipInfo_json.hasOwnProperty('VirusTotal')){
                    ip_info_dict['url'] = String(this.round(ipInfo_json['VirusTotal']['URL'],5))
                    ip_info_dict['down'] = String(this.round(ipInfo_json['VirusTotal']['down_file'],5))
                    ip_info_dict['ref'] = String(this.round(ipInfo_json['VirusTotal']['ref_file'],5))
                    ip_info_dict['com'] = String(this.round(ipInfo_json['VirusTotal']['com_file'],5))
                }
                else{
                    ip_info_dict['url'] = '-';
                    ip_info_dict['down'] = '-';
                    ip_info_dict['ref'] = '-';
                    ip_info_dict['com'] = '-';
                }

                if(ipInfo_json.hasOwnProperty('asn')){
                    ip_info_dict['asn'] = ipInfo_json['asn']['asnorg']
                }
                else{
                ip_info_dict['asn'] = '-'
                }

                if(ipInfo_json.hasOwnProperty('geocountry')){
                    ip_info_dict['geo'] = this.country_code[ipInfo_json['geocountry']]}

                if(typeof ip_info_dict['geo']  == 'undefined'){
                    ip_info_dict['geo'] = '-'
                }

                if(ipInfo_json.hasOwnProperty('SNI')){
                ip_info_dict['SNI'] = ipInfo_json['SNI']
                }
                else{
                ip_info_dict['SNI'] = '-'
                }

                if(ipInfo_json.hasOwnProperty('reverse_dns')){
                ip_info_dict['reverse_dns'] = ipInfo_json['reverse_dns']}
                else{ip_info_dict['reverse_dns'] = '-'}

            resolve(ip_info_dict)
            }

        }
        catch(err){
            console.log('Check getIPInfo in kalipso_listtable.js. Error: ', err)
            reject(err)
        }

        })
        })
    }


}

module.exports = {ListTableClass:ListTable}
