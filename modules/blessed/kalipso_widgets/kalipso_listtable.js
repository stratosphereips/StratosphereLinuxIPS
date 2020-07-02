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
              ip_info_dict['down'] = String(this.round(ipInfo_json['VirusTotal']['down'],5))
              ip_info_dict['ref'] = String(this.round(ipInfo_json['VirusTotal']['ref'],5))
              ip_info_dict['com'] = String(this.round(ipInfo_json['VirusTotal']['com'],5))
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
              if(letters_string.trim().length > 40){
                    var letter_string_chunks = this.chunkString(tuple_info[0].trim(),40);
                    async.forEachOf(letter_string_chunks, (chunk,ind,callback)=>{
                      var row2 = [];
                      if(ind == 0){
                        row2.push(key,chunk,dns_resolution,Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                      }
                      else{row2.push('',chunk,'','','','' ,'', '' , '');}
                        data.push(row2);
                        callback(null);
                    }, (err)=>{
                      if(err){console.log(err);}
                    })}
              else{     
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
              if(letters_string.trim().length > 40){
                    var letter_string_chunks = this.chunkString(tuple_info[0].trim(),40);
                    async.forEachOf(letter_string_chunks, (chunk,ind,callback)=>{
                      var row2 = [];
                      if(ind == 0){
                        row2.push(key,chunk,dns_resolution,Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                      }
                      else{row2.push('',chunk,'','','','' ,'', '' , '');}
                        data.push(row2);
                        callback(null);
                    }, (err)=>{
                      if(err){console.log(err);}
                    })}
              else{     
                row.push(key,letters_string,dns_resolution, Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
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

}
module.exports = ListTable