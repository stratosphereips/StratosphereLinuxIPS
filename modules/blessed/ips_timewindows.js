var redis = require('redis')
  , redis_ips_with_profiles = redis.createClient()
  , redis_tree = redis.createClient()
  , redis_tws_for_ip = redis.createClient()
  , redis_ip_info = redis.createClient()
  , redis_get_timeline = redis.createClient()
  , redis_outtuples_timewindow = redis.createClient()
  , redis_timeline_ip = redis.createClient()
  ,redis_blocked_tws = redis.createClient()
  , async = require('async')
  , blessed = require('blessed')
  , contrib = require('blessed-contrib')
  , fs = require('fs')
  , screen = blessed.screen()
  , color = require('chalk');
const stripAnsi = require('strip-ansi');

const clipboardy = require('clipboardy');
screen.dockBorders=true;
let country_loc = {};
fs.readFile('country.txt', 'utf8', function(err,data) {
    if(err) throw err;
    
    let splitted = data.toString().split(";");
    for (let i = 0; i<splitted.length; i++) {
        let splitLine = splitted[i].split(":");
        try{
          country_loc[splitLine[0]] = splitLine[1].split(",");}
        catch(err){
        }
    }
});




var ip_timewindow_outTuple = {};


function blockedTW(){ 
  return new Promise(function(resolve,reject){
    var blockedTWs = {};
    redis_blocked_tws.smembers("BlockedProfTW",(err,reply)=>{
    async.each(reply,function(blocked_line,callback){
      var blocked_list = blocked_line.split('_');
      if(!Object.keys(blockedTWs).includes(blocked_list[1])){
        blockedTWs[blocked_list[1]] = [];
        blockedTWs[blocked_list[1]].push(blocked_list[2])
      }
      else{
        blockedTWs[blocked_list[1]].push(blocked_list[2])
      }
      callback(null)
    },function(err){
      if(err){
        console.log(err);
      }
     else{resolve(blockedTWs)}
    })
  })
})}

// set up elements of the interface.

var grid = new contrib.grid({
  rows: 6,
  cols: 6,
  screen: screen
});

var table_timeline =  grid.set(0.5, 1, 4.3, 5, contrib.table, 
  {keys: true
  , vi:true
  , style:{border:{ fg:'blue'}}
  , scrollbar: true
  , label: "Timeline"
  , columnWidth:[200]})
, box_generic_dashboard = grid.set(2,2, 1.5, 2,blessed.box,{
      top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      label:'GENERIC DASHBOARD',
      tags: true,
      keys: true,
      
      style:{bg:'cyan',fg:'red',bold:true,
      border:{ bg:'red',fg:'red',type: 'line'
      ,bold: true},
      label:{fg:'magenta'}
    },
      vi:true,
      scrollable: true,
      alwaysScroll: true,
    scrollbar: {
        ch: ' ',
        inverse: true
      },
    
  })

  ,table_outTuples_listtable = grid.set(0,0,5.7,6, blessed.listtable, {
      keys: true,
      mouse: true,
  
      tags: true,
      // interactive: false,
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
    // ,table_inTuples = grid.set(0,0,5.7,6, blessed.listtable, {
    //   keys: true,
    //   mouse: true,
  
    //   tags: true,
    //   // interactive: false,
    //   border: 'line',
    //   style: {
    //     bg: 'blue'
    //   },
    //   style: {
    //     header: {
    //       fg: 'blue',
    //       bold: true
    //     },
    //     cell: {
    //       fg: 'magenta',
    //       selected: {
    //         bg: 'blue'
    //       }
    //     }
    //   },
    //   align: 'left'
    // })


,listtable_est_srcPort = grid.set(0,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}

    })
,listtable_notEst_srcPort = grid.set(2.8,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_est_dstIPs = grid.set(0,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_notEst_dstIPs = grid.set(2.8,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_est_dstPort = grid.set(0,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_notEst_dstPort = grid.set(2.8,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_est_dstPortClient = grid.set(0,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_notEst_dstPortClient = grid.set(2.8,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_est_dstPortClientIps = grid.set(0,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
,listtable_notEst_dstPortClientIps = grid.set(2.8,0,2.8,2, blessed.listtable, {
      border: 'line'
  , style: {border: {fg:'blue'}}
    })
  , tree =  grid.set(0,0,5.7,1,contrib.tree,
  { vi:true 
  , style: {fg:'green',border: {fg:'blue'}}
  , template: { lines: true }
  , label: 'Ips from slips'})

  , box_ip = grid.set(0, 1, 0.5, 5, blessed.box,
      {top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      content: "SELECT IP TO SEE IPS INFO!",
      tags: true,
       style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      border: {
      type: 'line'
    }})

 , box_evidence = grid.set(4.8,1, 0.9, 5,blessed.box,{
      top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      label:'Evidence',
      tags: true,
      keys: true,
      style:{
        border:{ fg:'blue',type: 'line'},
        focus: {border:{ fg:'magenta'}
    }},
      vi:true,
      scrollable: true,
      alwaysScroll: true,
    scrollbar: {
        ch: ' ',
        inverse: true
      },

  })


, map = grid.set(0, 0, 5.7, 6,contrib.map,{label: 'World Map',style:{border: {fg:'blue'}}
})

, help_list_bar = grid.set(5.7,0,0.4,6,blessed.listbar,{
  style:{
        border:{ fg:'blue'}},
      keys: false,
      style: {
        prefix: {
          fg: 'yellow'
        },
        item: {
        },
        selected:{fg:'red'}
      },
      autoCommandKeys: true,
      commands:
       {
            'main':{
              keys : ' '
            },
            
            'srcPortClient': {
              keys: ['e']
                        },
            'dstIPsClient': {
              keys: ['c']
                        },
            'dstPortServer': {
              keys: ['b']
                        },
            'dstPortsClient': {
              keys: ['p']
                        },
            'dstPortsClientIPs': {
              keys: ['n']
                        },
            
              'OutTuples': {
              keys: ['h']},

              'map': {
              keys: ['m']
                        },
              'InTuples': {
              keys: ['i']},
              'reload':{
              keys : ['o']
            },
                        

          }
}),
gaugeList_est_srcPort = grid.set(0.3, 2, 2.6, 4, contrib.gaugeList,
      {
      style:{
        border:{ fg:'blue'},
         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_notEst_srcPort = grid.set(3.1, 2, 2.6, 4, contrib.gaugeList,
      {

        style:{
          border:{ fg:'blue'},
         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_est_dstIPs = grid.set(0.3, 2, 2.6, 4, contrib.gaugeList,
      {

      style:{
          border:{ fg:'blue'},
        
         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_notEst_dstIPs = grid.set(3.1, 2, 2.6, 4, contrib.gaugeList,
      {
        style:{
          border:{ fg:'blue'},

         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    )
gaugeList_est_dstPort = grid.set(0.3, 2, 2.6, 4, contrib.gaugeList,
      {

      style:{
          border:{ fg:'blue'},

         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_notEst_dstPort = grid.set(3.1, 2, 2.6, 4, contrib.gaugeList,
      {
        style:{
          border:{ fg:'blue'},

         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_est_dstPortClient = grid.set(0.3, 2, 2.6, 4, contrib.gaugeList,
      {

      style:{
          border:{ fg:'blue'},

         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_notEst_dstPortClient = grid.set(3.1, 2, 2.6, 4, contrib.gaugeList,
      {
        style:{
          border:{ fg:'blue'},

         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_est_dstPortClientIps = grid.set(0.3, 2, 2.6, 4, contrib.gaugeList,
      {

      style:{
          border:{ fg:'blue'},

         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    ),
gaugeList_notEst_dstPortClientIps = grid.set(3.1, 2, 2.6, 4, contrib.gaugeList,
      {
        style:{
          border:{ fg:'blue'},

         focus: {
      border:{ fg:'magenta'}
    }},
      keys:true,
        gaugeSpacing: 1,
        gaugeHeight: 1,
        gauges:[]
      }
    )
var gauge_number = 9;
var timeline_length;
box_generic_dashboard.setFront()
box_generic_dashboard.focus()
gaugeList_notEst_dstPort.hide()
listtable_notEst_dstPort.hide()
gaugeList_est_dstPort.hide()
listtable_est_dstPort.hide()
gaugeList_notEst_dstPortClient.hide()
listtable_notEst_dstPortClient.hide()
gaugeList_est_dstPortClient.hide()
listtable_est_dstPortClient.hide()
gaugeList_notEst_dstPortClientIps.hide()
listtable_notEst_dstPortClientIps.hide()
gaugeList_est_dstPortClientIps.hide()
listtable_est_dstPortClientIps.hide()
gaugeList_notEst_srcPort.hide()
listtable_notEst_srcPort.hide()
gaugeList_notEst_dstIPs.hide()
listtable_notEst_dstIPs.hide()
gaugeList_est_dstIPs.hide()
listtable_est_dstIPs.hide()
table_outTuples_listtable.hide()
gaugeList_est_srcPort.hide()
listtable_est_srcPort.hide()


map.hide()
box_generic_dashboard.setContent('\n\n Welcome to Kalipso v0.1, Stratosphere Linux IPS v0.6.1\n\n https://stratosphereips.org\n\n Press TAB to exit this widget')
var focus_widget = tree;
var bar_state_four_two = true;
var bar_state_one = true;
var bar_state_two = true; 
var bar_state_three = true;
var bar_state_four = true;
var box_hotkeys_state = true;
var map_state = true;
var box_hotkeys_state = true;
var box_generic_dashboard_status = false;

function clean_widgets(){
  box_evidence.setContent('');
  table_timeline.setData({headers:[''], data: [['']]})
  table_outTuples_listtable.setItems('')
  box_ip.setContent('')
}

function hide_widgets(){
  gaugeList_notEst_dstPortClient.hide()
  listtable_notEst_dstPortClient.hide()
  gaugeList_est_dstPortClient.hide()
  listtable_est_dstPortClient.hide()
  gaugeList_notEst_dstPort.hide()
  listtable_notEst_dstPort.hide()
  gaugeList_est_dstPort.hide()
  listtable_est_dstPort.hide()
  listtable_est_srcPort.hide()
  gaugeList_notEst_srcPort.hide()
  listtable_notEst_srcPort.hide()
  gaugeList_est_srcPort.hide()
  listtable_est_dstIPs.hide()
  gaugeList_notEst_dstIPs.hide()
  listtable_notEst_dstIPs.hide()
  gaugeList_est_dstIPs.hide()
  gaugeList_notEst_dstPortClientIps.hide()
  listtable_notEst_dstPortClientIps.hide()
  gaugeList_est_dstPortClientIps.hide()
  listtable_est_dstPortClientIps.hide()
  // help_list_bar.hide()
  tree.hide()
  box_evidence.hide()
  table_timeline.hide()
  box_ip.hide()
  table_outTuples_listtable.hide()  

  map.hide()
}

function show_widgets(){
  help_list_bar.show()
  tree.show()
  box_evidence.show()
  table_timeline.show()
  box_ip.show()
  focus_widget.focus()

}

// var number_bars = Math.floor((2*bar_two_srcPortClient.width-2*bar_two_srcPortClient.options.xOffset)/(bar_two_srcPortClient.options.barSpacing+2*bar_two_srcPortClient.options.barWidth));

screen.render() 

function chunkString (str, len) {
  const size = Math.ceil(str.length/len)
  const r = Array(size)
  let offset = 0
  
  for (let i = 0; i < size; i++) {
    r[i] = str.substr(offset, len)
    offset += len
  }
  
  return r
}


String.prototype.repeat = function(length) {
 return Array(length + 1).join(this);
};

function round(value, decimals) {
  return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
};
 
//function to fill in data for a stacked bars
function bar_setdata(bar, counter, data, number){
  bar.clear()
  bar.setData(
      { barCategory: data[1].slice(counter,counter+number)
      , stackedCategory: ['totalflows', 'totalpkt','totalbytes']
      , data: data[0].slice(counter,counter+number)})
};

function tcp_udp_connections_dstPortsClient(key, key2,reply){    
  
  var data_listtable = [];
  var data_gaugeList = [];
  
  try{
    var obj_tcp = JSON.parse(reply[key]);
    

    var keys_tcp = Object.keys(obj_tcp);
  }
  catch(err){   
    var obj_tcp =[];
    var keys_tcp = [];
    }

  async.each(keys_tcp, function(key_TCP_est, callback) {
    
    var service_info = obj_tcp[key_TCP_est];
    var dst_ips = []

    dst_ips = Object.keys(service_info["dstips"]);
    var dst_ips_connections = Object.values(service_info["dstips"]);

    async.forEachOf(dst_ips, function(dst_ip_counter,dst_ip_index, callback){
      var row = [];
        var listtable_est_dstPort = [];
      listtable_est_dstPort.push('TCP/'+key_TCP_est,String(dst_ip_counter),String(dst_ips_connections[dst_ip_index]));
      data_listtable.push(listtable_est_dstPort)
      data_listtable.push([])
      row.push(round(Math.log(dst_ips_connections[dst_ip_index]),0));

      data_gaugeList.push({stack:row})
      callback();

    }, function(err){
      if( err ) {
        console.log('unable to create user');
      }
      // console.log()
    });
    callback();
  }, function(err) {
    if( err ) {
      console.log('unable to create user');
    } else {

    try{
      var obj_udp = JSON.parse(reply[key2]);
      var keys_udp = Object.keys(obj_udp);

    }
    catch(err){
      var obj_udp = []
      var keys_udp = []
      

    }

  async.each(keys_udp, function(key_UDP_est, callback) {
    var service_info = obj_udp[key_UDP_est];
    var dst_ips = Object.keys(service_info["dstips"]);
    var dst_ips_connections = Object.values(service_info["dstips"]);
    async.forEachOf(dst_ips, function(dst_ip_counter,dst_ip_index, callback){
      var row = [];
    var listtable_est_dstPort = [];
      listtable_est_dstPort.push('UDP/'+key_UDP_est,String(dst_ip_counter),String(dst_ips_connections[dst_ip_index]));
      data_listtable.push(listtable_est_dstPort)
      data_listtable.push([])
      row.push(round(Math.log(dst_ips_connections[dst_ip_index]),0));
      data_gaugeList.push({stack:row})
      callback();

    }, function(err){
      if( err ) {
        console.log('unable to create user');
      }})
    callback()
    }, function(err) {
      if( err ) {
        console.log('unable to create user');
      }
    });
  }
});
return [data_listtable, data_gaugeList]} 


//function to fill in the information about the map(loc and lot of a countries)
function setMap(ips){
  
  redis_ip_info.hgetall('IPsInfo', (err,reply)=>{
    async.each(ips, function(ip,callback){
      try{
      var inf = JSON.parse(reply[ip])
      }
      catch(err){
        return;
      }
      var country = inf["geocountry"]
      
      geoloc = country_loc[" "+country]
      
      if(geoloc!=undefined && geoloc !='Private'){
      
      var loc =country_loc[" "+country]
      map.addMarker({"lon" : loc[1], "lat" : loc[0], color: "red", char: "X" })}      
      callback();


  }, function(err){
    if(err){
      console.log(err)
    };  
  })

  })
  
};


//function to fill the info about bars (srcPortsServer, dstPortsClient)
function tcp_udp_connections(key, key2,reply){    
  var data_listtable = [];
  var data_gaugeList = [];
  
  try{
    var obj_tcp = JSON.parse(reply[key]);
    var keys_tcp = Object.keys(obj_tcp);
  }
  catch(err){   
    var obj_tcp =[];
    var keys_tcp = [];
    }

  async.each(keys_tcp, function(key_TCP_est, callback) {
    
    var service_info = obj_tcp[key_TCP_est];
    var row = [];
    var listtable_est_srcPort = [];
    listtable_est_srcPort.push('TCP/'+key_TCP_est,String(service_info['totalflows']), String(service_info['totalpkt']), String(service_info['totalbytes']))
    data_listtable.push(listtable_est_srcPort)
    data_listtable.push([])
    row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
    data_gaugeList.push({stack:row})
    callback();
  }, function(err) {
    if( err ) {
      console.log('unable to create user');
    } else {

    try{
      var obj_udp = JSON.parse(reply[key2]);
      var keys_udp = Object.keys(obj_udp);
    }
    catch(err){
      var obj_udp = []
      var keys_udp = []
    }

  async.each(keys_udp, function(key_UDP_est, callback) {
    var listtable_est_srcPort = [];
    var service_info = obj_udp[key_UDP_est];
    var row = [];
    listtable_est_srcPort.push('UDP/'+key_UDP_est,String(service_info['totalflows']), String(service_info['totalpkt']), String(service_info['totalbytes']))
    data_listtable.push(listtable_est_srcPort)
    data_listtable.push([])
    row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
    data_gaugeList.push({stack:row})
    callback()
    }, function(err) {
      if( err ) {
        console.log('unable to create user');
      }
    });
  }
});
return [ data_listtable, data_gaugeList]}

function timewindows_list_per_ip(tw){

  /*
  create a list of dictionaries with tws(to set the tree). [{'tw1':{},'tw2':{}"}]
  */
  var temp_list = []
  var dict = {};
  for(i=0; i<tw.length; i++){
    dict[tw[i]] = {}};
    temp_list.push(dict);
  return temp_list;
 };


function getIpInfo_box_ip(ip,mode){
  /*
  retrieves IPsInfo from redis.
  */

  return new Promise(function(resolve, reject) {
    redis_timeline_ip.hget("IPsInfo",ip,(err,reply)=>{
      var ip_info_str = "";
      var ip_info_dict = {'asn':'', 'geocountry':'', 'VirusTotal':''}
      var ip_info_dict_outtuple = {'asn':'', 'geocountry':'', 'VirusTotal':''}

     try{
        var obj = JSON.parse(reply);
        var ip_values =  Object.values(obj);
        var ip_keys = Object.keys(obj);

        if(ip_keys.includes('VirusTotal')){
          var vt = obj['VirusTotal'];
          var vt_string ='VirusTotal : URL : ' + round(vt['URL'],5)+', down_file : ' + round(vt['down_file'],5)  + ', ref_file : '+ round(vt['ref_file'],5) + ', com_file : ' + round(vt['com_file'],5); 
          ip_info_dict['VirusTotal'] = vt_string;
          ip_info_dict_outtuple['VirusTotal'] = obj['VirusTotal']
        }

        if(ip_keys.includes('asn')){
          ip_info_dict_outtuple['asn']=obj['asn'];
          var len_asn =  obj['asn'].length
          if(len_asn>33){
            ip_info_dict['asn'] = obj['asn'].slice(0,33);}
          else{
            var rep = 33- len_asn;
            ip_info_dict['asn'] = obj['asn']+" ".repeat(rep) 
          }
        }
        else{ip_info_dict['asn'] = ' '.repeat(33);}

        if(ip_keys.includes('geocountry')){
          ip_info_dict_outtuple['geocountry']=obj['geocountry'];
          var len_geocountry = obj['geocountry'].length;
          if(len_geocountry > 33){
          ip_info_dict['geocountry'] = obj['geocountry'].slice(0,33);}
          else{
            var rep = 33 - len_geocountry;
            ip_info_dict['geocountry'] = obj['geocountry']+" ".repeat(rep);
          }
        }
        else{ip_info_dict['geocountry'] = ' '.repeat(33);}
          ip_info_str = Object.values(ip_info_dict).join("|");
        if(mode == 1)box_ip.setContent(ip_info_str);
          box_ip.setLabel(ip)
          screen.render();
          resolve(ip_info_dict_outtuple);
        }
    catch (err){
        ip_info_str = " ".repeat(33) + "|"+" ".repeat(33) + "|"+" ".repeat(33)
        box_ip.setContent(ip_info_str);
        box_ip.setLabel('')
        screen.render();
        resolve(ip_info_dict)}
    })
  })
};



 function setDataTuples(table, data){
  table.setData(data);
  table.show()
  table.focus()
 }
function getEvidence(reply){
  /*
  retrieves IPsInfo from redis.
  */
  var ev = ''
  try{
    var obj = JSON.parse(reply);
    var keys = Object.keys(obj);
    async.each(keys, (key,callback)=>{
      ev = ev+'{bold}'+color.green(key)+'{/bold}'+" "+obj[key]+'\n'
      callback();
      }, function(err){
        if(err);
          box_evidence.setContent(ev);
      })
      screen.render();}
  catch (err){
    return;
    }
};
var ips_with_timewindows = {}

function set_tree_data(timewindows_list, blockedTW){
  /*
  sets ips and their tws for the tree.

  */
  // console.log(timewindows_list)
  var ips_with_profiles = Object.keys(timewindows_list);
  var explorer = { extended: true
  , children: function(self){
      var result = {};
             try {
            if (!self.childrenContent) {
          // var blockedTW = {};
          //   blockedTW = Object.assign({}, blockedTWs);
            for(i=0;i<ips_with_profiles.length;i++){
              var tw = timewindows_list[ips_with_profiles[i]];
              child = ips_with_profiles[i];
              var sorted_tws = sortTWs(blockedTW,tw[0], child)
            if(Object.keys(blockedTW).includes(child)){
              result[child] = { name:color.red(child), extended:false, children: sorted_tws};
            }
            else{
              result[child] = { name:child, extended:false, children: sorted_tws};
            }
           
            }
            }else
        result = self.childrenContent;
        } catch (e){}
        return result;
    }
}
return explorer;};


function sortTWs(blocked,tws_dict, ip){
  // var new_keys = []
  var blocked_tws = blocked[ip];
  var keys = Object.keys(tws_dict); // or loop over the object to get the array
// keys will be in any order
   keys.sort(); // maybe use custom sort, to change direction use .reverse()
// keys now will be in wanted order
  var temp_tws_dict = {};
  for (var i=0; i<keys.length; i++) { // now lets iterate in sort order
      var key = keys[i];
      if(blocked_tws != undefined && blocked_tws.includes(key)){
        temp_tws_dict[color.red(key)] = {};}
      else{
        temp_tws_dict[key] = {};}
  } 
  // console.log(temp_tws_dict)
  return temp_tws_dict;
  }

function getTreeData(key){
    if(key.includes('timeline')){
        var key_list = key.split('_');
        if(!Object.keys(ips_with_timewindows).includes(key_list[1])){
          ips_with_timewindows[key_list[1]]  = [];
          ips_with_timewindows[key_list[1]][0] = {};
          ips_with_timewindows[key_list[1]][0][key_list[2]]={};}
        else{
           ips_with_timewindows[key_list[1]][0][key_list[2]]={};
        }
    }
}
function timewindows_promises(reply) {
    return Promise.all(reply.map( key_redis => getTreeData(key_redis)))
      .then(blockedTW()
      .then(function(blocked_dict){tree.setData(set_tree_data(ips_with_timewindows,blocked_dict)); screen.render();return;}))
}

redis_tree.keys('*', (err,reply)=>{
    timewindows_promises(reply);
})        

screen.key('o', function(ch, key){
  clean_widgets();
  redis_tree.keys('*', (err,reply)=>{
    timewindows_promises(reply);
}) 
  hide_widgets();
  show_widgets();
  screen.render();

})
var timeline_reply_global  = {};
var ip;
var timewindow;
tree.on('select',function(node){
  
  screen.key('w',function(ch,key){
    clipboardy.writeSync(stripAnsi(node.name));
    clipboardy.readSync();
  })
    clean_widgets()

    if(!node.name.includes('timewindow')){
      getIpInfo_box_ip(stripAnsi(node.name), 1);}
      
    else{

      ip  = stripAnsi(node.parent.name);
      timewindow = stripAnsi(node.name);

      box_ip.setLabel('')

      redis_outtuples_timewindow.hgetall("profile_"+ip+"_"+timewindow, (err,reply)=>{
        var ips = [];
        timeline_reply_global = reply;
        map.innerMap.draw(null);
        getEvidence(reply['Evidence']);
        try {
  		var obj_outTuples = JSON.parse(reply["OutTuples"]);
	}
	catch(error) {
  		var obj_outTuples = JSON.parse(reply["InTuples"]);
		}
        var keys = Object.keys(obj_outTuples);
        async.each(keys, function(key,callback){        
          var outTuple_ip = key.split(':')[0];
          ips.push(outTuple_ip); 
          callback(null);  
        },function(err) {
      if( err ) {
	console.log(ip)
        console.log('unable to create user');
      } else {
        setMap(ips)
      screen.render();  
      }
      });})
    

      //get the timeline of a selected ip
  redis_get_timeline.lrange("profile_"+ip+"_"+timewindow+'_timeline',0,-1, (err,reply)=>{
      var data = [];
      if(reply.length < 1){
        table_timeline.setData({headers:[node.parent.name+" "+node.name], data: data});
          // console.log(data.length)
          timeline_length = data.length;
          screen.render();
      }
      else{
      async.each(reply, function(line, callback){
        var row = [];
        var line_arr = line.split(" ")
	if(line_arr[0].includes('/')){
	
        var index_to_from = line_arr.indexOf('to')
	if(index_to_from <= 0){
	  index_to_from = line_arr.indexOf('from');}
        var index_ip = index_to_from +1;
	var index_port_protocol = index_to_from+2;
	var index_sent = index_port_protocol + 2
	var index_rec = index_sent + 2
	var index_total = index_rec + 2
	line_arr[1]= line_arr[1].substring(0,8);
	for(i = 2; i<index_to_from; i++){
		line_arr[i] = color.rgb(51, 153, 255)(line_arr[i]);}
	  var keywords = ['Query','Answers','SN', 'Trusted', 'Resumed', 'Version']
	  var http_keywords = ['method','Status', 'UA', 'MIME', 'Ref']
	  var attention_keywords = ['No', 'Protocol' ]
	  line_arr[index_ip]= color.rgb(0, 153, 153)(line_arr[index_ip])
	  line_arr[index_port_protocol]=color.bold.yellow(line_arr[index_port_protocol])
	  line_arr[index_sent + 1] = color.rgb(255, 153, 51)(line_arr[index_sent + 1])
	  line_arr[index_rec + 1] = color.rgb(255, 153, 51)(line_arr[index_rec + 1])
	  line_arr[index_total + 1] = color.rgb(255, 153, 51)(line_arr[index_total + 1])
	  if(index_total + 2 < line_arr.length && attention_keywords.some(el => line_arr[index_total + 2].includes(el))){
	for(ind = index_total+2; ind < line_arr.length; ind++){		
		line_arr[ind] = color.red(line_arr[ind])		}
}
	  else{increase = 0
	  while(true){
	  increase = increase + 2
	  if(index_total+increase +1 >= line_arr.length){
		break;}

	  if(keywords.some(el => line_arr[index_total + increase].includes(el))){
		line_arr[index_total + increase+1] = color.rgb(255, 153, 51)(line_arr[index_total+increase + 1])}
}}
	  timeline_line = line_arr.join(" ");
	  row.push(timeline_line.replace(/\|.*/,''));
	  data.push(row);}
	else{
	  http = JSON.parse(line)
	for (let [key, value] of Object.entries(http)) {
	  row = []
	  line = key.padStart(21+key.length) +':' +color.rgb(51, 153, 255)(value);
	  row.push(line);
          data.push(row);
}

}
        callback();
      },function(err) {
        if( err ) {
          console.log('unable to create user');
        } else {
          table_timeline.setData({headers:[node.parent.name+" "+node.name], data: data});
          timeline_length = data.length;
          screen.render();
        }
    });}
  })

    }})
 // screen.key('i', function(ch, key) {
 //          hide_widgets();
 //          help_list_bar.selectTab(6)
 //          bar_state_one = true;
 //          bar_state_two = true; 
 //          bar_state_three = true;
 //          bar_state_four = true;
 //          bar_state_four_two = true;
 //          // box_hotkeys_state = true;
 //          map_state = true;
 //          if(box_hotkeys_state){
         
 //              if(timeline_reply_global == null){
 //                table_inTuples.setItems('');} 
 //              else if(Object.keys(ip_timewindow_inTuple).includes(ip+timewindow)){
 //                setDataTuples(table_inTuples,ip_timewindow_inTuple[ip+timewindow]);

 //              }
 //              else{
 //              try {
 //      var obj_inTuples = JSON.parse(timeline_reply_global["InTuples"]);
 //    }
 //    catch(error) {

 //        }
 //              var keys = Object.keys(obj_inTuples);
 //              var data = [];
 //              async.each(keys, function(key,callback){
 //                var ip_dict = {'asn':'', 'geocountry':'', 'URL':'','down':'','ref':'', 'com':''}
 //                var row = [];
 //                var tuple_info = obj_inTuples[key];
 //                var inTuple_ip = key.split(':')[0];
 //                getIpInfo_box_ip(inTuple_ip,0).then(function(result_dict){
 //                  var ipInfo_dict_keys = Object.keys(result_dict)
 //                  if(ipInfo_dict_keys.includes('asn')){
 //                    ip_dict['asn'] = result_dict['asn']
 //                  }
 //                  if(ipInfo_dict_keys.includes('geocountry')){
 //                    ip_dict['geocountry'] = result_dict['geocountry']
 //                  }
 //                  if(ipInfo_dict_keys.includes('VirusTotal')){
 //                    ip_dict['URL'] = String(round(result_dict['VirusTotal']['URL'],3));
 //                    ip_dict['down'] = String(round(result_dict['VirusTotal']['down_file'],3));
 //                    ip_dict['ref'] = String(round(result_dict['VirusTotal']['ref_file'],3));
 //                    ip_dict['com'] = String(round(result_dict['VirusTotal']['com_file'],3));
 //                  }
 //                if(tuple_info[0].trim().length>40){
 //                  var k = chunkString(tuple_info[0].trim(),40);
                
 //                  async.forEachOf(k, function(ctr,ind, callback){
 //                    var row2 = [];
 //                    if(ind == 0){
 //                      row2.push(key,ctr,Object.values(ip_dict)[0].slice(0,20), Object.values(ip_dict)[1], Object.values(ip_dict)[2], Object.values(ip_dict)[3],Object.values(ip_dict)[4], Object.values(ip_dict)[5]);
 //                    }
 //                    else{row2.push('',ctr, '', '' , '');}
 //                      data.push(row2);
 //                      callback(null);
 //                  }, function(err){
 //                    if(err){
 //                      console.log('kamila',err);}
 //                  })

 //                }  
 //          else{     
 //            row.push(key,tuple_info[0], Object.values(ip_dict)[0].slice(0,20), Object.values(ip_dict)[1], Object.values(ip_dict)[2], Object.values(ip_dict)[3],Object.values(ip_dict)[4], Object.values(ip_dict)[5]);
 //            data.push(row)}
 //            callback(null);
 //          })  
 //        },function(err) {
 //      if( err ) {
 //        console.log('unable to create user');
 //      } else {
 //        data.unshift(['key','string','asn','geocountry','url','down','ref','com'])
 //        ip_timewindow_inTuple[ip+timewindow] = data;
 //        setDataTuples(table_inTuples,data);
 //        screen.render();  
 //        }
 //      });
 //      }}
 //      else{
 //        table_inTuples.setItems('');
 //        table_inTuples.hide()
 //        help_list_bar.selectTab(0)
 //        show_widgets()}
 //        box_hotkeys_state =! box_hotkeys_state
 //        screen.render();
 //        });

 screen.key('h', function(ch, key) {
          hide_widgets();
          help_list_bar.selectTab(6)
          bar_state_one = true;
          bar_state_two = true; 
          bar_state_three = true;
          bar_state_four = true;
          bar_state_four_two = true;
          // box_hotkeys_state = true;
          map_state = true;
          if(box_hotkeys_state){
         
              if(timeline_reply_global == null){
                table_outTuples_listtable.setItems('');} 
              else if(Object.keys(ip_timewindow_outTuple).includes(ip+timewindow)){
                setDataTuples(table_outTuples_listtable,ip_timewindow_outTuple[ip+timewindow]);

              }
              else{
              try {
  		var obj_outTuples = JSON.parse(timeline_reply_global["OutTuples"]);
		}
		catch(error) {
  			var obj_outTuples = JSON.parse(timeline_reply_global["InTuples"]);
		}
              var keys = Object.keys(obj_outTuples);
              var data = [];
              async.each(keys, function(key,callback){
                var ip_dict = {'asn':'', 'geocountry':'', 'URL':'','down':'','ref':'', 'com':''}
                var row = [];
                var tuple_info = obj_outTuples[key];
                var outTuple_ip = key.split(':')[0];
                getIpInfo_box_ip(outTuple_ip,0).then(function(result_dict){
                  var ipInfo_dict_keys = Object.keys(result_dict)
                  if(ipInfo_dict_keys.includes('asn')){
                    ip_dict['asn'] = result_dict['asn']
                  }
                  if(ipInfo_dict_keys.includes('geocountry')){
                    ip_dict['geocountry'] = result_dict['geocountry']
                  }
                  if(ipInfo_dict_keys.includes('VirusTotal')){
                    ip_dict['URL'] = String(round(result_dict['VirusTotal']['URL'],3));
                    ip_dict['down'] = String(round(result_dict['VirusTotal']['down_file'],3));
                    ip_dict['ref'] = String(round(result_dict['VirusTotal']['ref_file'],3));
                    ip_dict['com'] = String(round(result_dict['VirusTotal']['com_file'],3));
                  }
                if(tuple_info[0].trim().length>40){
                  var k = chunkString(tuple_info[0].trim(),40);
                
                  async.forEachOf(k, function(ctr,ind, callback){
                    var row2 = [];
                    if(ind == 0){
                      row2.push(key,ctr,Object.values(ip_dict)[0].slice(0,20), Object.values(ip_dict)[1], Object.values(ip_dict)[2], Object.values(ip_dict)[3],Object.values(ip_dict)[4], Object.values(ip_dict)[5]);
                    }
                    else{row2.push('',ctr, '', '' , '');}
                      data.push(row2);
                      callback(null);
                  }, function(err){
                    if(err){
                      console.log('kamila',err);}
                  })

                }  
          else{     
            row.push(key,tuple_info[0], Object.values(ip_dict)[0].slice(0,20), Object.values(ip_dict)[1], Object.values(ip_dict)[2], Object.values(ip_dict)[3],Object.values(ip_dict)[4], Object.values(ip_dict)[5]);
            data.push(row)}
            callback(null);
          })  
        },function(err) {
      if( err ) {
        console.log('unable to create user');
      } else {
        data.unshift(['key','string','asn','geocountry','url','down','ref','com'])
        ip_timewindow_outTuple[ip+timewindow] = data;
        setDataTuples(table_outTuples_listtable,data);
        screen.render();  
        }
      });
      }}
      else{
        table_outTuples_listtable.setItems('');
        table_outTuples_listtable.hide()
        help_list_bar.selectTab(0)
        show_widgets()}
        box_hotkeys_state =! box_hotkeys_state
        screen.render();
        });

     
//display two bars of dstPortsServer established and non established connections

  screen.key('b', function(ch, key) {
  help_list_bar.selectTab(3)

        hide_widgets()
    bar_state_one = true;
    // bar_state_two = true; 
    bar_state_three = true;
    box_hotkeys_state = true;
    bar_state_four = true;
    bar_state_four_two = true;
    map_state = true;
    var gauge_counter1 = 0;
    var gauge_counter2 = 0;
    var listtable_counter1 = 0;
    var listtable_counter2 = 0;
    if(bar_state_two){
      var est_connections_dstPortsServer = tcp_udp_connections("dstPortsServerTCPEstablished","dstPortsServerUDPEstablished",timeline_reply_global);
      var notEst_connections_dstPortsServer = tcp_udp_connections("dstPortsServerTCPNotEstablished","dstPortsServerUDPNotEstablished",timeline_reply_global);
      var est_bar_one_number_dstPortsServer = Math.ceil(est_connections_dstPortsServer[1].length / gauge_number);
      var notEst_bar_one_number_dstPortsServer = Math.ceil(notEst_connections_dstPortsServer[1].length / gauge_number);

      gaugeList_notEst_dstPort.setGauges(notEst_connections_dstPortsServer[1].slice(0,gauge_number))
      gaugeList_est_dstPort.setGauges(est_connections_dstPortsServer[1].slice(0,gauge_number))
      var data_est =  [['estdstPortServer', 'totalflows', 'totalpkts','totalbytes'],[]]
      data_est.push(...est_connections_dstPortsServer[0].slice(0,gauge_number*2))
      listtable_est_dstPort.setData(data_est)

      var data_notest =  [['notEstdstPortServer', 'totalflows', 'totalpkts','totalbytes'],[]]
      data_notest.push(...notEst_connections_dstPortsServer[0].slice(0,gauge_number*2))
      listtable_notEst_dstPort.setData(data_notest) 

      gaugeList_est_dstPort.show()
      gaugeList_notEst_dstPort.show()
      listtable_notEst_dstPort.show()
      listtable_est_dstPort.show()
      gaugeList_est_dstPort.focus()
      screen.render();

    screen.key('down', function(ch, key){
      if(gaugeList_est_dstPort.focused == true || gaugeList_est_dstIPs.focused == true){
        if(gauge_counter1 >= (est_bar_one_number_dstPortsServer-1)*gauge_number);
        else{
          var data_est_dstPortServer =[['estdstPortServer', 'totalflows', 'totalpkts','totalbytes'],[]];
          listtable_counter1 += gauge_number*2;
          gauge_counter1 += gauge_number;
          data_est_dstPortServer.push(...est_connections_dstPortsServer[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstPort.setData(data_est_dstPortServer);
          gaugeList_est_dstPort.setGauges(est_connections_dstPortsServer[1].slice(gauge_counter1,gauge_counter1 + gauge_number));
          screen.render();}
      }
      else{
        if(gauge_counter2 >= (notEst_bar_one_number_dstPortsServer-1)*gauge_number);
        else{
          var data_notEst_dstPortServer =[['notEstdstPortServer', 'totalflows', 'totalpkts','totalbytes'],[]];
          listtable_counter2 += gauge_number*2;
          gauge_counter2 += gauge_number;
          data_notEst_dstPortServer.push(...notEst_connections_dstPortsServer[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstPort.setData(data_notEst_dstPortServer);
          gaugeList_notEst_dstPort.setGauges(notEst_connections_dstPortsServer[1].slice(gauge_counter2,gauge_counter2 + gauge_number));
          screen.render();}
      }
      })

    screen.key('up', function(ch, key){
      if(gaugeList_est_dstPort.focused == true ||gaugeList_est_dstIPs.focused == true){
        listtable_counter1 -= gauge_number*2;
        gauge_counter1 -= gauge_number;
        if(listtable_counter1 <=0){listtable_counter1 = 0; gauge_counter1 = 0}
          var data_est_dstPortServer =[['estdstPortServer', 'totalflows', 'totalpkts','totalbytes'],[]];
          data_est_dstPortServer.push(...est_connections_dstPortsServer[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstPort.setData(data_est_dstPortServer);
          gaugeList_est_dstPort.setGauges(est_connections_dstPortsServer[1].slice(gauge_counter1,gauge_counter1+gauge_number));
          screen.render();
      }
      else{
        listtable_counter2 -=gauge_number*2;
        gauge_counter2 -= gauge_number;
        if(listtable_counter2 <=0){listtable_counter2 = 0; gauge_counter2 = 0}
          var data_notEst_dstPortServer = [['notEstdstPortServer', 'totalflows', 'totalpkts','totalbytes'],[]];
          data_notEst_dstPortServer.push(...notEst_connections_dstPortsServer[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstPort.setData(data_notEst_dstPortServer);
          gaugeList_notEst_dstPort.setGauges(notEst_connections_dstPortsServer[1].slice(gauge_counter2,gauge_counter2+gauge_number));
          screen.render();  }
    })

    }
    else{

        listtable_est_dstPort.hide()
        listtable_notEst_dstPort.hide()
        gaugeList_notEst_dstPort.hide()
        gaugeList_est_dstPort.hide()
        show_widgets();
  help_list_bar.selectTab(0)

      }
    bar_state_two = !bar_state_two;
    screen.render();
  
});
  screen.key('n', function(ch, key) {
    help_list_bar.selectTab(5)
    hide_widgets()

    bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    box_hotkeys_state = true;
    map_state = true;
    // bar_state_four = true;
    bar_state_four_two = true;
    var gauge_counter1 = 0;
    var gauge_counter2 = 0;
    var listtable_counter1 = 0;
    var listtable_counter2 = 0;
    if(bar_state_four){
      var est_connections_dstPortsClient = tcp_udp_connections_dstPortsClient("DstPortsClientTCPEstablished","DstPortsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_dstPortsClient = tcp_udp_connections_dstPortsClient("DstPortsClientTCPNotEstablished","DstPortsClientUDPNotEstablished",timeline_reply_global);
      var est_bar_one_number_dstPortsClient = Math.ceil(est_connections_dstPortsClient[1].length / gauge_number);
      var notEst_bar_one_number_dstPortsClient = Math.ceil(notEst_connections_dstPortsClient[1].length / gauge_number);

      gaugeList_notEst_dstPortClientIps.setGauges(notEst_connections_dstPortsClient[1].slice(0,gauge_number))
      gaugeList_est_dstPortClientIps.setGauges(est_connections_dstPortsClient[1].slice(0,gauge_number))
      var data_est =  [['estdstPortClient',  'IP','Number of connections'],[]]
      data_est.push(...est_connections_dstPortsClient[0].slice(0,gauge_number*2))
      // console.log(data_est)
      listtable_est_dstPortClientIps.setData(data_est)

      var data_notest =  [['notEstdstPortClient', 'IP','Number of connections'],[]]
      data_notest.push(...notEst_connections_dstPortsClient[0].slice(0,gauge_number*2))
      listtable_notEst_dstPortClientIps.setData(data_notest) 

      gaugeList_est_dstPortClientIps.show()
      gaugeList_notEst_dstPortClientIps.show()
      listtable_notEst_dstPortClientIps.show()
      listtable_est_dstPortClientIps.show()
      gaugeList_est_dstPortClientIps.focus()
      screen.render();

    screen.key('down', function(ch, key){
      if(gaugeList_est_dstPortClientIps.focused == true){
        if(gauge_counter1 >= (est_bar_one_number_dstPortsClient-1)*gauge_number);
        else{
          var data_est_dstPortClientIps =[['estdstPortClient', 'IP','Number of connections'],[]];
          listtable_counter1 += gauge_number*2;
          gauge_counter1 += gauge_number;
          data_est_dstPortClientIps.push(...est_connections_dstPortsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstPortClientIps.setData(data_est_dstPortClientIps);
          gaugeList_est_dstPortClientIps.setGauges(est_connections_dstPortsClient[1].slice(gauge_counter1,gauge_counter1 + gauge_number));
          screen.render();}
      }
      else{
        if(gauge_counter2 >= (notEst_bar_one_number_dstPortsClient-1)*gauge_number);
        else{
          var data_notEst_dstPortClientIps =[['notEstdstPortClient', 'IP','Number of connections'],[]];
          listtable_counter2 += gauge_number*2;
          gauge_counter2 += gauge_number;
          data_notEst_dstPortClientIps.push(...notEst_connections_dstPortsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstPortClientIps.setData(data_notEst_dstPortClientIps);
          gaugeList_notEst_dstPortClientIps.setGauges(notEst_connections_dstPortsClient[1].slice(gauge_counter2,gauge_counter2 + gauge_number));
          screen.render();}
      }
      })

    screen.key('up', function(ch, key){
      if(gaugeList_est_dstPortClientIps.focused == true){
        listtable_counter1 -= gauge_number*2;
        gauge_counter1 -= gauge_number;
        if(listtable_counter1 <=0){listtable_counter1 = 0; gauge_counter1 = 0}
          var data_est_dstPortClientIps =[['estdstPortClient', 'IP','Number of connections'],[]];
          data_est_dstPortClientIps.push(...est_connections_dstPortsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstPortClientIps.setData(data_est_dstPortClientIps);
          gaugeList_est_dstPortClientIps.setGauges(est_connections_dstPortsClient[1].slice(gauge_counter1,gauge_counter1+gauge_number));
          screen.render();
      }
      else{
        listtable_counter2 -=gauge_number*2;
        gauge_counter2 -= gauge_number;
        if(listtable_counter2 <=0){listtable_counter2 = 0; gauge_counter2 = 0}
          var data_notEst_dstPortClientIps = [['notEstdstPortClient', 'IP','Number of connections'],[]];
          data_notEst_dstPortClientIps.push(...notEst_connections_dstPortsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstPortClientIps.setData(data_notEst_dstPortClientIps);
          gaugeList_notEst_dstPortClientIps.setGauges(notEst_connections_dstPortsClient[1].slice(gauge_counter2,gauge_counter2+gauge_number));
          screen.render();  }
    })

    }
    else{


        listtable_est_dstPortClientIps.hide()
        listtable_notEst_dstPortClientIps.hide()
        gaugeList_notEst_dstPortClientIps.hide()
        gaugeList_est_dstPortClientIps.hide()
        show_widgets();
      help_list_bar.selectTab(0)

      }
    bar_state_four =! bar_state_four;
    screen.render()
  
});

  screen.key('p', function(ch, key) {
  help_list_bar.selectTab(4)

    hide_widgets()

    bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    box_hotkeys_state = true;
    map_state = true;
    bar_state_four = true;
    // bar_state_four_two = true;
    var gauge_counter1 = 0;
    var gauge_counter2 = 0;
    var listtable_counter1 = 0;
    var listtable_counter2 = 0;
    if(bar_state_four_two){
      var est_connections_dstPortsClient = tcp_udp_connections("DstPortsClientTCPEstablished","DstPortsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_dstPortsClient = tcp_udp_connections("DstPortsClientTCPNotEstablished","DstPortsClientUDPNotEstablished",timeline_reply_global);
      var est_bar_one_number_dstPortsClient = Math.ceil(est_connections_dstPortsClient[1].length / gauge_number);
      var notEst_bar_one_number_dstPortsClient = Math.ceil(notEst_connections_dstPortsClient[1].length / gauge_number);

      gaugeList_notEst_dstPortClient.setGauges(notEst_connections_dstPortsClient[1].slice(0,gauge_number))
      gaugeList_est_dstPortClient.setGauges(est_connections_dstPortsClient[1].slice(0,gauge_number))
      var data_est =  [['estdstPortClient',  'totalflows','totalpkts','totalbytes'],[]]
      data_est.push(...est_connections_dstPortsClient[0].slice(0,gauge_number*2))
      listtable_est_dstPortClient.setData(data_est)

      var data_notest =  [['notEstdstPortClient',  'totalflows','totalpkts','totalbytes'],[]]
      data_notest.push(...notEst_connections_dstPortsClient[0].slice(0,gauge_number*2))
      listtable_notEst_dstPortClient.setData(data_notest) 

      gaugeList_est_dstPortClient.show()
      gaugeList_notEst_dstPortClient.show()
      listtable_notEst_dstPortClient.show()
      listtable_est_dstPortClient.show()
      gaugeList_est_dstPortClient.focus()
      screen.render();

    screen.key('down', function(ch, key){
      if(gaugeList_est_dstPortClient.focused == true){
        if(gauge_counter1 >= (est_bar_one_number_dstPortsClient-1)*gauge_number);
        else{
          var data_est_dstPortClient =[['estdstPortClient',  'totalflows','totalpkts','totalbytes'],[]];
          listtable_counter1 += gauge_number*2;
          gauge_counter1 += gauge_number;
          data_est_dstPortClient.push(...est_connections_dstPortsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstPortClient.setData(data_est_dstPortClient);
          gaugeList_est_dstPortClient.setGauges(est_connections_dstPortsClient[1].slice(gauge_counter1,gauge_counter1 + gauge_number));
          screen.render();}
      }
      else{
        if(gauge_counter2 >= (notEst_bar_one_number_dstPortsClient-1)*gauge_number);
        else{
          var data_notEst_dstPortClient =[['notEstdstPortClient',  'totalflows','totalpkts','totalbytes'],[]];
          listtable_counter2 += gauge_number*2;
          gauge_counter2 += gauge_number;
          data_notEst_dstPortClient.push(...notEst_connections_dstPortsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstPortClient.setData(data_notEst_dstPortClient);
          gaugeList_notEst_dstPortClient.setGauges(notEst_connections_dstPortsClient[1].slice(gauge_counter2,gauge_counter2 + gauge_number));
          screen.render();}
      }
      })

    screen.key('up', function(ch, key){
      if(gaugeList_est_dstPortClient.focused == true){
        listtable_counter1 -= gauge_number*2;
        gauge_counter1 -= gauge_number;
        if(listtable_counter1 <=0){listtable_counter1 = 0; gauge_counter1 = 0}
          var data_est_dstPortClient =[['estdstPortClient',  'totalflows','totalpkts','totalbytes'],[]];
          data_est_dstPortClient.push(...est_connections_dstPortsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstPortClient.setData(data_est_dstPortClient);
          gaugeList_est_dstPortClient.setGauges(est_connections_dstPortsClient[1].slice(gauge_counter1,gauge_counter1+gauge_number));
          screen.render();
      }
      else{
        listtable_counter2 -=gauge_number*2;
        gauge_counter2 -= gauge_number;
        if(listtable_counter2 <=0){listtable_counter2 = 0; gauge_counter2 = 0}
          var data_notEst_dstPortClient = [['notEstdstPortClient',  'totalflows','totalpkts','totalbytes'],[]];
          data_notEst_dstPortClient.push(...notEst_connections_dstPortsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstPortClient.setData(data_notEst_dstPortClient);
          gaugeList_notEst_dstPortClient.setGauges(notEst_connections_dstPortsClient[1].slice(gauge_counter2,gauge_counter2+gauge_number));
          screen.render();  }
    })

    }
    else{

        listtable_est_dstPortClient.hide()
        listtable_notEst_dstPortClient.hide()
        gaugeList_notEst_dstPortClient.hide()
        gaugeList_est_dstPortClient.hide()
        show_widgets();
      help_list_bar.selectTab(0)

      }
    bar_state_four_two =! bar_state_four_two;
    screen.render()
  
});


//display to bars of SrcPortsClient established and non established connections    
 screen.key('e', function(ch, key) {
  help_list_bar.selectTab(1)

    hide_widgets()
    // bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    box_hotkeys_state = true;
    map_state = true;
    bar_state_four = true;
    bar_state_four_two = true;
    var gauge_counter1 = 0;
    var gauge_counter2 = 0;
    var listtable_counter1 = 0;
    var listtable_counter2 = 0;
    if(bar_state_one){
      var est_connections_srcPortsClient = tcp_udp_connections("SrcPortsClientTCPEstablished","SrcPortsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_srcPortsClient = tcp_udp_connections("SrcPortsClientTCPNotEstablished","SrcPortsClientUDPNotEstablished",timeline_reply_global);
      var est_bar_one_number_srcPortsClient = Math.ceil(est_connections_srcPortsClient[1].length / gauge_number);
      var notEst_bar_one_number_srcPortsClient = Math.ceil(notEst_connections_srcPortsClient[1].length / gauge_number);

      gaugeList_notEst_srcPort.setGauges(notEst_connections_srcPortsClient[1].slice(0,gauge_number))
      gaugeList_est_srcPort.setGauges(est_connections_srcPortsClient[1].slice(0,gauge_number))
      var data_est =  [['estSrcPortClient', 'totalflows', 'totalpkts','totalbytes'],[]]
      data_est.push(...est_connections_srcPortsClient[0].slice(0,gauge_number*2))
      listtable_est_srcPort.setData(data_est)

      var data_notest =  [['notEstSrcPortClient', 'totalflows', 'totalpkts','totalbytes'],[]]
      data_notest.push(...notEst_connections_srcPortsClient[0].slice(0,gauge_number*2))
      listtable_notEst_srcPort.setData(data_notest) 

      gaugeList_est_srcPort.show()
      gaugeList_notEst_srcPort.show()
      listtable_notEst_srcPort.show()
      listtable_est_srcPort.show()
      gaugeList_est_srcPort.focus()
      screen.render();
     
    screen.key('down', function(ch, key){
      if(gaugeList_est_srcPort.focused == true || gaugeList_est_dstIPs.focused == true){
        if(gauge_counter1 >= (est_bar_one_number_srcPortsClient-1)*gauge_number);
        else{
          var data_est_srcPortClient =[['estSrcPortClient','totalflows', 'totalpkts','totalbytes'],[]];
          listtable_counter1 += gauge_number*2;
          gauge_counter1 += gauge_number;
          data_est_srcPortClient.push(...est_connections_srcPortsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_srcPort.setData(data_est_srcPortClient);
          gaugeList_est_srcPort.setGauges(est_connections_srcPortsClient[1].slice(gauge_counter1,gauge_counter1 + gauge_number));
          screen.render();}
      }
      else{
        if(gauge_counter2 >= (notEst_bar_one_number_srcPortsClient-1)*gauge_number);
        else{
          var data_notEst_srcPortClient =[['notEstSrcPortClient', 'totalflows', 'totalpkts','totalbytes'],[]];
          listtable_counter2 += gauge_number*2;
          gauge_counter2 += gauge_number;
          data_notEst_srcPortClient.push(...notEst_connections_srcPortsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_srcPort.setData(data_notEst_srcPortClient);
          gaugeList_notEst_srcPort.setGauges(notEst_connections_srcPortsClient[1].slice(gauge_counter2,gauge_counter2 + gauge_number));
          screen.render();}
      }
      })

    screen.key('up', function(ch, key){
      if(gaugeList_est_srcPort.focused == true ||gaugeList_est_dstIPs.focused == true){
        listtable_counter1 -= gauge_number*2;
        gauge_counter1 -= gauge_number;
        if(listtable_counter1 <=0){listtable_counter1 = 0; gauge_counter1 = 0}
          var data_est_srcPortClient =[['estSrcPortClient', 'totalflows', 'totalpkts','totalbytes'],[]];
          data_est_srcPortClient.push(...est_connections_srcPortsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_srcPort.setData(data_est_srcPortClient);
          gaugeList_est_srcPort.setGauges(est_connections_srcPortsClient[1].slice(gauge_counter1,gauge_counter1+gauge_number));
          screen.render();
      }
      else{
        listtable_counter2 -=gauge_number*2;
        gauge_counter2 -= gauge_number;
        if(listtable_counter2 <=0){listtable_counter2 = 0; gauge_counter2 = 0}
          var data_notEst_srcPortClient = [['notEstSrcPortClient', 'totalflows', 'totalpkts','totalbytes'],[]];
          data_notEst_srcPortClient.push(...notEst_connections_srcPortsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_srcPort.setData(data_notEst_srcPortClient);
          gaugeList_notEst_srcPort.setGauges(notEst_connections_srcPortsClient[1].slice(gauge_counter2,gauge_counter2+gauge_number));
          screen.render();  }
    })

    }
    else{

        listtable_est_srcPort.hide()
        listtable_notEst_srcPort.hide()
        gaugeList_notEst_srcPort.hide()
        gaugeList_est_srcPort.hide()
        show_widgets();
  help_list_bar.selectTab(0)

      }
    bar_state_one = !bar_state_one;
    screen.render()
  
});


//display to bars of dstIPsClient established and non established connections
screen.key('c', function(ch, key) {
  help_list_bar.selectTab(2)
    hide_widgets()
    bar_state_one = true;
    bar_state_two = true; 
    // bar_state_three = true;
    bar_state_four = true;
    bar_state_four_two = true;
    box_hotkeys_state = true;
    map_state = true;
    var gauge_counter1 = 0;
    var gauge_counter2 = 0;
    var listtable_counter1 = 0;
    var listtable_counter2 = 0;
    if(bar_state_three){
      var est_connections_dstIPsClient = tcp_udp_connections("DstIPsClientTCPEstablished","DstIPsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_dstIPsClient = tcp_udp_connections("DstIPsClientTCPNotEstablished","DstIPsClientUDPNotEstablished",timeline_reply_global);
      var est_bar_one_number_dstIPsClient= Math.ceil(est_connections_dstIPsClient[1].length / gauge_number);
      var notEst_bar_one_number_dstIPsClient = Math.ceil(notEst_connections_dstIPsClient[1].length / gauge_number);

      gaugeList_notEst_dstIPs.setGauges(notEst_connections_dstIPsClient[1].slice(0,gauge_number))
      gaugeList_est_dstIPs.setGauges(est_connections_dstIPsClient[1].slice(0,gauge_number))
      var data_est =  [['estDstIPsClient', 'totalflows', 'totalpkts','totalbytes'],[]]
      data_est.push(...est_connections_dstIPsClient[0].slice(0,gauge_number*2))
      listtable_est_dstIPs.setData(data_est)

      var data_notest =  [['notEstDstIPsClient', 'totalflows', 'totalpkts','totalbytes'],[]]
      data_notest.push(...notEst_connections_dstIPsClient[0].slice(0,gauge_number*2))
      listtable_notEst_dstIPs.setData(data_notest) 

      gaugeList_est_dstIPs.show()
      gaugeList_notEst_dstIPs.show()
      listtable_notEst_dstIPs.show()
      listtable_est_dstIPs.show()
      gaugeList_est_dstIPs.focus()
      screen.render();

    screen.key('down', function(ch, key){
      if(gaugeList_est_dstIPs.focused == true || gaugeList_est_srcPort.focused == true){
        if(gauge_counter1 >= (est_bar_one_number_dstIPsClient-1)*gauge_number);
        else{
          var data_est_dstIPsClient =[['estDstIPsClient', 'totalflows', 'totalpkts','totalbytes'],[]];
          listtable_counter1 += gauge_number*2;
          gauge_counter1 += gauge_number;
          data_est_dstIPsClient.push(...est_connections_dstIPsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstIPs.setData(data_est_dstIPsClient);
          gaugeList_est_dstIPs.setGauges(est_connections_dstIPsClient[1].slice(gauge_counter1,gauge_counter1 + gauge_number));
          screen.render();}
      }
      else{
        if(gauge_counter2 >= (notEst_bar_one_number_dstIPsClient-1)*gauge_number);
        else{
          var data_notEst_dstIPsClient =[['notEstDstIPsClient', 'totalflows', 'totalpkts','totalbytes'],[]];
          listtable_counter2 += gauge_number*2;
          gauge_counter2 += gauge_number;
          data_notEst_dstIPsClient.push(...notEst_connections_dstIPsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstIPs.setData(data_notEst_dstIPsClient);
          gaugeList_notEst_dstIPs.setGauges(notEst_connections_dstIPsClient[1].slice(gauge_counter2,gauge_counter2 + gauge_number));
          screen.render();}
      }
      })

    screen.key('up', function(ch, key){
      if(gaugeList_est_dstIPs.focused == true || gaugeList_est_srcPort.focused == true){
        listtable_counter1 -= gauge_number*2;
        gauge_counter1 -= gauge_number;
        if(listtable_counter1 <=0){listtable_counter1 = 0; gauge_counter1 = 0}
          var data_est_dstIPsClient =[['estDstIPsClient', 'totalflows', 'totalpkts','totalbytes'],[]];
          data_est_dstIPsClient.push(...est_connections_dstIPsClient[0].slice(listtable_counter1,listtable_counter1 + gauge_number*2));
          listtable_est_dstIPs.setData(data_est_dstIPsClient);
          gaugeList_est_dstIPs.setGauges(est_connections_dstIPsClient[1].slice(gauge_counter1,gauge_counter1+gauge_number));
          screen.render();
      }
      else{
        listtable_counter2 -= gauge_number*2; 
        gauge_counter2 -= gauge_number;
        if(listtable_counter2 <=0){listtable_counter2 = 0; gauge_counter2 = 0}
          var data_notEst_dstIPsClient = [['notEstDstIPsClient', 'totalflows', 'totalpkts','totalbytes'],[]];
          data_notEst_dstIPsClient.push(...notEst_connections_dstIPsClient[0].slice(listtable_counter2,listtable_counter2 + gauge_number*2));
          listtable_notEst_dstIPs.setData(data_notEst_dstIPsClient);
          gaugeList_notEst_dstIPs.setGauges(notEst_connections_dstIPsClient[1].slice(gauge_counter2,gauge_counter2+gauge_number));
          screen.render();  }
    })

    }
    else{

        listtable_est_dstIPs.hide()
        listtable_notEst_dstIPs.hide()
        gaugeList_notEst_dstIPs.hide()
        gaugeList_est_dstIPs.hide()
        show_widgets();
        help_list_bar.selectTab(0);
    }
    bar_state_three = !bar_state_three;
    screen.render()
});


screen.key('m', function(ch, key) {
  hide_widgets()
  help_list_bar.selectTab(7)
  bar_state_one = true;
  bar_state_two = true; 
  bar_state_three = true;
  bar_state_four = true;
  bar_state_four_two = true;
  box_hotkeys_state = true;

  if(map_state){
    map.show()
  }
  else{
     show_widgets()
      map.hide()  
      help_list_bar.selectTab(0)
    }
    map_state = !map_state;
    screen.render()

});
//    screen.key('C-w',function(ch,key){
//     // console.log(table_timeline.rows.ritems)
//   clipboardy.writeSync(typeof(table_timeline.rows.ritems));
// clipboardy.readSync();
// })

// table_timeline.rows.on('focus', (item, index) => {

//   // table_timeline.options.data = (Math.round(item.selected / timeline_length *100,0));

// });

table_timeline.rows.on('select', (item, index) => {
  var timeline_line = item.content.split(" ");
  var index_to = timeline_line.indexOf('to')
  var timeline_ip = timeline_line[index_to +1].slice(6,-7)
  getIpInfo_box_ip(stripAnsi(timeline_ip),1)

});
// screen.key("g", function(ch,key){
//   box_generic_dashboard.toggle()
//   box_generic_dashboard.focus();
//   screen.render();
// })




screen.key(['tab'], function(ch, key) {
  if(box_generic_dashboard.focused == true){
    box_generic_dashboard.hide()
    focus_widget = tree
    tree.style.border.fg = 'magenta'
    tree.focus();
  }
  else if(gaugeList_est_srcPort.focused == true){
    gaugeList_notEst_srcPort.focus()
  }
  else if(gaugeList_notEst_srcPort.focused == true){
    gaugeList_est_srcPort.focus()
  }
  else if(gaugeList_notEst_dstIPs.focused == true){
    gaugeList_est_dstIPs.focus()
  }
  else if(gaugeList_est_dstIPs.focused == true){
    gaugeList_notEst_dstIPs.focus()
  }
  else if(gaugeList_notEst_dstPort.focused == true){
    gaugeList_est_dstPort.focus()
  }
  else if(gaugeList_est_dstPort.focused == true){
    gaugeList_notEst_dstPort.focus()
  }
  else if(gaugeList_notEst_dstPortClient.focused == true){
    gaugeList_est_dstPortClient.focus()
  }
  else if(gaugeList_est_dstPortClient.focused == true){
    gaugeList_notEst_dstPortClient.focus()
  }
  else if(gaugeList_notEst_dstPortClientIps.focused == true){
    gaugeList_est_dstPortClientIps.focus()
  }
  else if(gaugeList_est_dstPortClientIps.focused == true){
    gaugeList_notEst_dstPortClientIps.focus()
  }
  else if(screen.focused == tree.rows){
    focus_widget =table_timeline
    tree.style.border.fg = 'blue'
    table_timeline.style.border.fg='magenta'
    table_timeline.focus();}
  else if(screen.focused == table_timeline.rows){
    table_timeline.style.border.fg='blue'
    focus_widget = box_evidence
    box_evidence.focus()}
  else{
    focus_widget = tree
    tree.style.border.fg = 'magenta'
    tree.focus();}
    screen.render()})



screen.key(['S-tab'], function(ch, key) {
  if(screen.focused == table_timeline.rows){
    focus_widget =tree;
    table_timeline.style.border.fg = 'blue'
    tree.style.border.fg='magenta'
    tree.focus();}

  else if(screen.focused == box_evidence){
    focus_widget = table_timeline;
    table_timeline.style.border.fg='magenta'
    table_timeline.focus();}
  else{
    focus_widget = box_evidence;
    tree.style.border.fg = 'blue'
    box_evidence.focus();}   
    screen.render();
});

screen.on('resize', function() {
  box_generic_dashboard.emit('attach');
  gaugeList_notEst_dstPort.emit('attach');
  listtable_notEst_dstPort.emit('attach');
  gaugeList_est_dstPort.emit('attach');
  listtable_est_dstPort.emit('attach');
  gaugeList_notEst_dstPortClient.emit('attach');
  listtable_notEst_dstPortClient.emit('attach');
  gaugeList_est_dstPortClient.emit('attach');
  listtable_est_dstPortClient.emit("attach");
  gaugeList_notEst_dstPortClientIps.emit("attach");
  listtable_notEst_dstPortClientIps.emit("attach");
  gaugeList_est_dstPortClientIps.emit("attach");
  listtable_est_dstPortClientIps.emit("attach");
  gaugeList_notEst_srcPort.emit("attach");
  listtable_notEst_srcPort.emit("attach");
  gaugeList_notEst_dstIPs.emit("attach");
  listtable_notEst_dstIPs.emit("attach");
  gaugeList_est_dstIPs.emit("attach");
  listtable_est_dstIPs.emit("attach");
  table_outTuples_listtable.emit("attach");
  gaugeList_est_srcPort.emit("attach");
  listtable_est_srcPort.emit("attach");
  help_list_bar.emit("attach");
  tree.emit("attach");
  box_evidence.emit("attach");
  table_timeline.emit("attach");
  box_ip.emit("attach");
  focus_widget.emit("attach");
});


screen.key(["escape", "q", "C-c"], function(ch, key) {
    return process.exit(0);
});
screen.render();
tree.style.border.fg = 'magenta';
