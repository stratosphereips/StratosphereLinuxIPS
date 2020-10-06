var async = require('async')

class ListTable{
  constructor(grid, blessed, contrib, redis_database,screen, characteristics){
      this.contrib = contrib
      this.screen = screen
      this.blessed = blessed
      this.grid = grid
      this.redis_database = redis_database
      this.widget = this.initListTable(characteristics);
}
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

  setData(data){
    /*
    To set data in the widget
    */
    this.widget.setData(data)
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
    To focus on the widget
    */
    this.widget.focus()
  }
  round(value, decimals) {
    /*
    Round number to specific decimals
    */
    return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
  }
    setDataIPInfo(data){
    /*
    To set IP info data in the widget
    */
    this.widget.setData(data)
    }

   setIPInfo(ip){
    /*
    Function to create dictionary with approptiate IP information
    */
    try{
      this.redis_database.getIpInfo(ip).then(redis_IpInfo_data=>{
        var ipInfo_data  = [['asn','geocountry','url','down','ref','com']]
        var ip_info_str = "";
        var ip_info_dict = {'asn':'', 'geocountry':'', 'VirusTotal':{'URL':'', 'down':'','ref':'','com':''}}

        var ipInfo_json = JSON.parse(redis_IpInfo_data);
        var ip_values =  Object.values(ipInfo_json);
        var ip_keys = Object.keys(ipInfo_json);

        if (ipInfo_json.hasOwnProperty('VirusTotal')){
          ip_info_dict['VirusTotal']['URL'] = String(this.round(ipInfo_json['VirusTotal']['URL'],5))
          ip_info_dict['VirusTotal']['down'] = String(this.round(ipInfo_json['VirusTotal']['down_file'],5))
          ip_info_dict['VirusTotal']['ref'] = String(this.round(ipInfo_json['VirusTotal']['ref_file'],5))
          ip_info_dict['VirusTotal']['com'] = String(this.round(ipInfo_json['VirusTotal']['com_file'],5))
        }
        if(ipInfo_json.hasOwnProperty('asn')){
          ip_info_dict['asn'] = ipInfo_json['asn']
        }
        if(ipInfo_json.hasOwnProperty('geocountry')){
          ip_info_dict['geocountry'] = ipInfo_json['geocountry']
        }
        ipInfo_data.push([ip_info_dict['asn'], ip_info_dict['geocountry'], ip_info_dict['VirusTotal']['URL'], ip_info_dict['VirusTotal']['down'],ip_info_dict['VirusTotal']['ref'],ip_info_dict['VirusTotal']['com']])
        this.setDataIPInfo(ipInfo_data)
        this.screen.render()
      })
    }
    catch (err){console.log(err)}
  }

  chunkString(str, len) {
    /*
    Function to split data in chuncks
    */
    const size = Math.ceil(str.length/len)
    const r = Array(size)
    let offset = 0
    
    for (let i = 0; i < size; i++) {
      r[i] = str.substr(offset, len)
      offset += len
    }
    
    return r
  }

  getIPInfo_dict(ip){
    /*
    Function to fill the dictionsry for the ip info dict
    */
    return new Promise ((resolve, reject)=>{this.redis_database.getIpInfo(ip)
      .then(redis_IpInfo_data=>{
          var ip_info_dict = {'asn':'', 'geocountry':'', 'URL':'', 'down':'','ref':'','com':''}
          if(redis_IpInfo_data==null)resolve(ip_info_dict)
          else{
            var ipInfo_json = JSON.parse(redis_IpInfo_data);
            var ip_values =  Object.values(ipInfo_json);
            var ip_keys = Object.keys(ipInfo_json);

            if (ipInfo_json.hasOwnProperty('VirusTotal')){
              ip_info_dict['URL'] = String(this.round(ipInfo_json['VirusTotal']['URL'],5))
              ip_info_dict['down'] = String(this.round(ipInfo_json['VirusTotal']['down_file'],5))
              ip_info_dict['ref'] = String(this.round(ipInfo_json['VirusTotal']['ref_file'],5))
              ip_info_dict['com'] = String(this.round(ipInfo_json['VirusTotal']['com_file'],5))
            }
            if(ipInfo_json.hasOwnProperty('asn')){
              ip_info_dict['asn'] = ipInfo_json['asn']
            }
            if(ipInfo_json.hasOwnProperty('geocountry')){
              ip_info_dict['geocountry'] = ipInfo_json['geocountry']
            }
            resolve( ip_info_dict)
          }
      })
    })    
  }

  setOutTuples(ip, timewindow){
    /*
    Function to combine data for outtuple hotkey - key, behavioral letters, asn, geocountry, VT
    */
    try{
      this.redis_database.getOutTuples(ip, timewindow)
      .then(redis_outTuples=>{
        var data = [['key','string','dns_resolution','asn','geocountry','url','down','ref','com']]
        if(redis_outTuples==null){this.setData(data);this.screen.render(); return;}
        else{
          var json_outTuples = JSON.parse(redis_outTuples)
          var keys = Object.keys(json_outTuples)
          async.each(keys,(key, callback)=>{
            var row = [];
            var tuple_info = json_outTuples[key];
            var outTuple_ip = key.split(':')[0];
            var letters_string = tuple_info[0]
            this.getIPInfo_dict(outTuple_ip)
            .then(ip_info_dict=>{
            this.redis_database.getDNSResolution(outTuple_ip).then(dns_resolution=>{
              var letter_string_chunks = this.chunkString(letters_string.trim(),40);
              var length_dns_resolution = dns_resolution.length
              var length_letter = letter_string_chunks.length
              if(dns_resolution){
              dns_resolution = JSON.parse(dns_resolution)}
              if(length_dns_resolution >1 || length_letter >1){
                  if(length_dns_resolution > length_letter){
                      async.forEachOf(dns_resolution, (dns,ind,callback)=>{
                          var row2 = [];
                          if(ind == 0){
                            row2.push(key,letter_string_chunks[ind],dns,Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                          }
                          else{
                            if(typeof letter_string_chunks[ind] == 'undefined'){
                               row2.push('','',dns_resolution[ind],'','','' ,'', '' , '');}
                            else{
                               row2.push('',letter_string_chunks[ind],dns,'','','' ,'', '' , '');}
                               }

                           data.push(row2);
                           callback(null);
                        }, (err)=>{
                          if(err){console.log(err);}
                        })
                    }
                  else if(length_letter > length_dns_resolution){
                    async.forEachOf(letter_string_chunks, (chunk,ind,callback)=>{
                      var row2 = [];
                      if(ind == 0){
                        if(typeof dns_resolution[ind] == 'undefined'){
                            row2.push(key,chunk,'',Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                        }
                        else{
                            row2.push(key,chunk,dns_resolution[ind],Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                        }
                      }
                      else{
                        if(typeof dns_resolution[ind]  == 'undefined'){
                         row2.push('',chunk,'','','','' ,'', '' , '');
                        }
                        else{
                        row2.push('',chunk,dns_resolution[ind],'','','' ,'', '' , '');}
                      }
                      data.push(row2);
                      callback(null);
                    }, (err)=>{
                      if(err){console.log(err);}
                    })}
                }
              else{
//              if( typeof dns_resolution === 'undefined'){dns_resolution = ''}
                row.push(key,letters_string, dns_resolution,Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                data.push(row)
              }
                callback(null);
            })})
          },(err)=>{
            if(err) {console.log(err)} 
            else {
              this.setData(data);
              this.screen.render();  
            }
          })
        }
      });
    } 
    catch(err){
      console.log(err)
    }
  }

  setInTuples(ip, timewindow){
    /*
    Function to combine data for outtuple hotkey - key, behavioral letters, asn, geocountry, VT
    */
    try{
      this.redis_database.getInTuples(ip, timewindow)
      .then(redis_outTuples=>{
        var data = [['key','string','dns_resolution','asn','geocountry','url','down','ref','com']]
        if(redis_outTuples==null){this.setData(data);this.screen.render(); return;}
        else{
          var json_outTuples = JSON.parse(redis_outTuples)
          var keys = Object.keys(json_outTuples)
          async.each(keys,(key, callback)=>{
            var row = [];
            var tuple_info = json_outTuples[key];
            var outTuple_ip = key.split(':')[0];
            var letters_string = tuple_info[0]
            this.getIPInfo_dict(outTuple_ip)
            .then(ip_info_dict=>{
              this.redis_database.getDNSResolution(outTuple_ip).then(dns_resolution=>{
              var letter_string_chunks = this.chunkString(letters_string.trim(),40);
              var length_dns_resolution = dns_resolution.length
              var length_letter = letter_string_chunks.length
              if(dns_resolution){
              dns_resolution = JSON.parse(dns_resolution)}
              if(length_dns_resolution >1 || length_letter >1){
                  if(length_dns_resolution > length_letter){
                      async.forEachOf(dns_resolution, (dns,ind,callback)=>{
                          var row2 = [];
                          if(ind == 0){
                            row2.push(key,letter_string_chunks[ind],dns,Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                          }
                          else{
                            if(typeof letter_string_chunks[ind] == 'undefined'){
                               row2.push('','',dns_resolution[ind],'','','' ,'', '' , '');}
                            else{
                               row2.push('',letter_string_chunks[ind],dns,'','','' ,'', '' , '');}
                               }

                           data.push(row2);
                           callback(null);
                        }, (err)=>{
                          if(err){console.log(err);}
                        })
                    }
                  else if(length_letter > length_dns_resolution){
                    async.forEachOf(letter_string_chunks, (chunk,ind,callback)=>{
                      var row2 = [];
                      if(ind == 0){
                        if(typeof dns_resolution[ind] == 'undefined'){
                            row2.push(key,chunk,'',Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                        }
                        else{
                            row2.push(key,chunk,dns_resolution[ind],Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                        }
                      }
                      else{
                        if(typeof dns_resolution[ind]  == 'undefined'){
                         row2.push('',chunk,'','','','' ,'', '' , '');
                        }
                        else{
                        row2.push('',chunk,dns_resolution[ind],'','','' ,'', '' , '');}
                      }
                      data.push(row2);
                      callback(null);
                    }, (err)=>{
                      if(err){console.log(err);}
                    })}
                }
              else{
//              if( typeof dns_resolution === 'undefined'){dns_resolution = ''}
                row.push(key,letters_string, dns_resolution,Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                data.push(row)
              }
                callback(null);
            })})
          },(err)=>{
            if(err) {console.log(err)} 
            else {
              this.setData(data);
              this.screen.render();  
            }
          })
        }
      });
    } 
    catch(err){
      console.log(err)
    }
  }
  setHelp(){
    var data = [['hotkey', 'description'],
                ['-h','help for hotkeys.']
                ['-e','src ports when the IP of the profile acts as clien. Total flows, packets and bytes going IN a specific source port.'],
                ['-d','dst IPs when the IP of the profile acts as client. Total flows, packets and bytes going TO a specific dst IP.'],
                ['-r','dst ports when the IP of the profile as server. Total flows, packets and bytes going TO a specific dst IP.'],
                ['-f','dst ports when the IP of the profile acted as client. Total flows, packets and bytes going TO a specific dst port.'],
                ['-t','dst ports when the IP of the profile acted  as client. The amount of connections to a dst IP on a specific port .'],
                ['-g','outTuples ‘IP-port-protocol’combined together with outTuples Behavioral letters, DNS resolution  of the IP, ASN, geo country and Virus Total summary.'],
                ['-y','inTuples ‘IP-port-protocol’combined together with inTuples Behavioral letters, DNS resolution  of the IP, ASN, geo country and Virus Total summary.'],
                ['-o','manually update the tree with profiles and timewindows. Default is 2 minutes. '],
                ['-q','exit the hotkey'],
                ['-ESC',' exit Kalipso']]
    this.setData(data)
    this.screen.render()
  }

}
module.exports = ListTable