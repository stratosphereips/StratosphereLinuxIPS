var async = require('async')
var fs = require('fs')

class ListTable{
    constructor(grid, blessed, contrib, redis_database,screen, characteristics,limit_letter_outtuple=0){
        this.contrib = contrib
        this.screen = screen
        this.blessed = blessed
        this.grid = grid
        this.redis_database = redis_database
        this.widget = this.initListTable(characteristics);
        this.limit_letter_outtuple = limit_letter_outtuple
        this.country_code = {}
        this.read_file().then(data=>{this.country_code = data})
}
    /*Initialise the widget ListTable and its parameters*/
    initListTable(characteristics){
        return this.grid.set(characteristics[0],characteristics[1],characteristics[2],characteristics[3], this.blessed.listtable, {
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
            this.screen.render()
        })
    }
        catch (err){
        console.log('Check setIPInfo in kalipso_listtable.js. Error: ',err)}
  }


    getIPInfo_dict(ip){
        return new Promise ((resolve, reject)=>{this.redis_database.getIpInfo(ip).then(redis_IpInfo_data=>{
        try{
            var ip_info_dict = {'asn':'', 'geo':'', 'SNI':'', 'reverse_dns':'', 'url':'', 'down':'','ref':'','com':''}
            if(redis_IpInfo_data==null)resolve(ip_info_dict)
            else{
                var ipInfo_json = JSON.parse(redis_IpInfo_data);
                var ip_values =  Object.values(ipInfo_json);
                var ip_keys = Object.keys(ipInfo_json);

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

    /*Combine data for the outtuple hotkey - key, behavioral letters, asn, geo VT*/
    setOutTuples(ip, timewindow){
        this.redis_database.getOutTuples(ip, timewindow).then(redis_outTuples=>{
            var data = [['Out Tuple','Flow Behavior','DNS Resolution','SNI','RDNS','AS','CN','Url','Down','Ref','Com']]
            if(redis_outTuples==null){this.setData(data);this.screen.render(); return;}
            var json_outTuples = JSON.parse(redis_outTuples)
            var keys = Object.keys(json_outTuples)
            async.each(keys,(key, callback)=>{
                var tuple_info = json_outTuples[key];
                var split_tuple = key.split(':')
                var outTuple_port = split_tuple[split_tuple.length-2];
                var outTuple_protocol = split_tuple[split_tuple.length -1]
                if(split_tuple.length > 3){var outTuple_ip = split_tuple.slice(0,split_tuple.length-2).join(':')}
                else{var outTuple_ip = split_tuple[0]}
                var letters_string = tuple_info[0].substr(0, this.limit_letter_outtuple)
                this.getIPInfo_dict(outTuple_ip).then(ip_info_dict =>{
                this.redis_database.getDNSResolution(outTuple_ip).then(all_dns_resolution=>{
                var letter_string_chunks = this.chunkString(letters_string.trim(),40);
                var length_letter = letter_string_chunks.length
                if(all_dns_resolution){all_dns_resolution = JSON.parse(all_dns_resolution)['domains']}
                var dns_resolution = all_dns_resolution
                var length_dns_resolution = dns_resolution.length
                var all_sni = ip_info_dict['SNI']
                var sni = all_sni.slice(Math.max(all_sni.length - 3, 0))
                var length_sni = sni.length
                // If dns resolution is not defined, use 0 
                if (length_dns_resolution == null) { length_dns_resolution = 0 }
                var max_length = Math.max(length_dns_resolution, length_letter, length_sni)
                var indexes_array = Array.from(Array(max_length).keys())

             async.forEach(indexes_array, (ind, callback)=>{
                var row = [];
                var temp_dns_resolution = ''
                var temp_str =''
                var temp_sni ='';

                if(dns_resolution[ind] != undefined){temp_dns_resolution = dns_resolution[ind]};

                if(sni[ind] != undefined &&
                    outTuple_port.localeCompare(sni[ind]["dport"]) ==0 &&
                    outTuple_protocol.localeCompare("tcp") == 0){
                    temp_sni = sni[ind]["server_name"];}

                if(letter_string_chunks[ind] != undefined){temp_str = letter_string_chunks[ind]}

                if(ind ==0){
                    row.push(key, temp_str, temp_dns_resolution,
                              temp_sni,ip_info_dict['reverse_dns'], ip_info_dict['asn'].slice(0,20), ip_info_dict['geo'],
                              ip_info_dict['url'], ip_info_dict['down'], ip_info_dict['ref'],
                              ip_info_dict['com'])}
                else{
                    row.push('', temp_str, temp_dns_resolution,
                              temp_sni, '', '','','','','','')}
                data.push(row)
                callback(null)
                }, (err)=>{if(err){console.log('Check setOutTuple in kalipso_listtable.js. Error: ', err);}})
                callback(null)
                })})
             },(err)=>{if(err){console.log('Check setOutTuple in kalipso_listtable.js. Error: ',err)}
                    else{
                      this.setData(data);
                      this.screen.render()}}
          )
          })
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
                var tuple_info = json_inTuples[key];
                var split_tuple = key.split(':')
                var inTuple_port = split_tuple[split_tuple.length-2];
                var inTuple_protocol = split_tuple[split_tuple.length -1]
                if(split_tuple.length > 3){var inTuple_ip = split_tuple.slice(0,split_tuple.length-2).join(':')}
                else{var inTuple_ip = split_tuple[0]}
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


  /*Set data for the help*/
    setHelp(){
        var data = [['hotkey', 'description'],
                    ['-h','help for hotkeys.'],
                    ['-e','src ports when the IP of the profile acts as clien. Total flows, packets and bytes going IN a specific source port.'],
                    ['-d','dst IPs when the IP of the profile acts as client. Total flows, packets and bytes going TO a specific dst IP.'],
                    ['-r','dst ports when the IP of the profile as server. Total flows, packets and bytes going TO a specific dst IP.'],
                    ['-f','dst ports when the IP of the profile acted as client. Total flows, packets and bytes going TO a specific dst port.'],
                    ['-t','dst ports when the IP of the profile acted  as client. The amount of connections to a dst IP on a specific port .'],
                    ['-i','outTuples ‘IP-port-protocol’combined together with outTuples Behavioral letters, DNS resolution  of the IP, ASN, geo country and Virus Total summary.'],
                    ['-y','inTuples ‘IP-port-protocol’combined together with inTuples Behavioral letters, DNS resolution  of the IP, ASN, geo country and Virus Total summary.'],
                    ['-z', 'evidences from all timewindows in the selected profile.' ],
                    ['-o','manually update the tree with profiles and timewindows. Default is 2 minutes. '],
                    ['-q','exit the hotkey'],
                    ['-ESC','exit Kalipso']]
        this.setData(data)
    }
}

module.exports = ListTable
