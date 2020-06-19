var async = require('async')
// var color = require('chalk')

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
      tags: true,
      // label:'OutTuples',
      interactive: true,
      border: 'line',
      style: {
        bg: 'blue'
      },
      style: {
        header: {
          fg: 'blue',
          bold: true
        },
        cell: {
          fg: 'magenta',
          selected: {
            bg: 'blue'
          }
        }
      },
      align: 'left'
    })
  }

  setData(data){
    this.widget.setData(data)
      }
  hide(){
    this.widget.hide()
      }
  show(){
    this.widget.show()
      }
  focus(){
    this.widget.focus()
      }
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

  getIPInfo_dict(ip){

    return new Promise ((resolve, reject)=>{this.redis_database.getIpInfo(ip).then(redis_IpInfo_data=>{
          var ip_info_dict = {'asn':'', 'geocountry':'', 'URL':'', 'down':'','ref':'','com':''}

          var ipInfo_json = JSON.parse(redis_IpInfo_data);
          var ip_values =  Object.values(ipInfo_json);
          var ip_keys = Object.keys(ipInfo_json);

          if (ipInfo_json.hasOwnProperty('VirusTotal')){
            ip_info_dict['VirusTotal']['URL'] = this.round(ipInfo_json['URL'],5)
            ip_info_dict['VirusTotal']['down'] = this.round(ipInfo_json['down'],5)
            ip_info_dict['VirusTotal']['ref'] = this.round(ipInfo_json['ref'],5)
            ip_info_dict['VirusTotal']['com'] = this.round(ipInfo_json['com'],5)
          }
          if(ipInfo_json.hasOwnProperty('asn')){
            ip_info_dict['asn'] = ipInfo_json['asn']
          }
          if(ipInfo_json.hasOwnProperty('geocountry')){
            ip_info_dict['geocountry'] = ipInfo_json['geocountry']
          }
          resolve( ip_info_dict)
    })
      })
      
  }
  setOutTuples(ip, timewindow){
    try{
      this.redis_database.getOutTuples(ip, timewindow).then(redis_outTuples=>{
        // console.log(redis_outTuples)
        var json_outTuples = JSON.parse(redis_outTuples)
        var keys = Object.keys(json_outTuples)
        var data = [['key','string','asn','geocountry','url','down','ref','com']]
        async.each(keys,(key, callback)=>{
          // colognsole.log(key)
          var row = [];
          var tuple_info = json_outTuples[key];
          var outTuple_ip = key.split(':')[0];
          var letters_string = tuple_info[0]
          this.getIPInfo_dict(outTuple_ip).then(ip_info_dict=>{
          if(letters_string.trim().length > 40){
                var letter_string_chunks = this.chunkString(tuple_info[0].trim(),40);
                async.forEachOf(letter_string_chunks, (chunk,ind,callback)=>{
                  var row2 = [];
                  if(ind == 0){
                    row2.push(key,chunk,Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
                  }
                  else{row2.push('',chunk, '', '' , '');}
                    data.push(row2);
                    callback(null);
                }, (err)=>{
                  if(err){console.log(err);}
                })}
          else{     
            row.push(key,letters_string, Object.values(ip_info_dict)[0].slice(0,20), Object.values(ip_info_dict)[1], Object.values(ip_info_dict)[2], Object.values(ip_info_dict)[3],Object.values(ip_info_dict)[4], Object.values(ip_info_dict)[5]);
            data.push(row)
          }
            callback(null);
          })
        },(err)=>{
          if( err ) {
            console.log(err);
          } else {
            this.setData(data);
            this.screen.render();  
            }})
      });
      } catch(err){
        console.log(err)
      }

    }

}
module.exports = ListTable