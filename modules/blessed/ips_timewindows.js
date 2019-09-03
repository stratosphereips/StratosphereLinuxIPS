var redis = require('redis')
  , redis_ips_with_profiles = redis.createClient()
  , redis_tree = redis.createClient()
  , redis_tws_for_ip = redis.createClient()
  , redis_ip_info = redis.createClient()
  , redis_get_timeline = redis.createClient()
  , redis_outtuples_timewindow = redis.createClient()
  , redis_detections_timewindow = redis.createClient()
  , redis_timeline_ip = redis.createClient()
  , async = require('async')
  , blessed = require('blessed')
  , contrib = require('blessed-contrib')
  , fs = require('fs')
  , screen = blessed.screen()
  , colors = require('colors');

screen.options.dockBorders=true;
//read countries  location
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


// set up elements of the interface.

var grid = new contrib.grid({
  rows: 6,
  cols: 6,
  screen: screen
});

var table_timeline =  grid.set(0.5, 1, 3.7, 5, contrib.table, 
  {keys: true
  , vi:true
  , scrollbar: true
  , label: "Timeline"
  , columnWidth:[200]})

  ,table_outTuples =  grid.set(5,1,1.8,2.5, contrib.table, 
  { keys: true
  , vi:true
  , scrollbar:true
  , label: "OutTuples"
   , columnWidth:[25,30,30,30,30]})

  , tree =  grid.set(0,0,5,1,contrib.tree,
  { vi:true 
  , style: {border: {fg:'magenta'}}
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

 , box_detections = grid.set(4.2, 1, 0.9, 2.5,blessed.box,{
      top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      label:'Detections',
      tags: true,
    vi:true,
    style:{
         focus: {
      border:{ fg:'magenta'}
    }},
    border: {
      type: 'line'
    }
  })
 , box_evidence = grid.set(4.2, 3.5, 0.9, 2.5,blessed.box,{
      top: 'center',
      left: 'center',
      width: '50%',
      height: '50%',
      label:'Evidence',
      tags: true,
      keys: true,
      style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      vi:true,
      scrollable: true,
      alwaysScroll: true,
    scrollbar: {
        ch: ' ',
        inverse: true
      },
    border: {
      type: 'line'
    },
  })
, box_hotkeys = grid.set(0, 0, 6, 6, blessed.text,
      {
      content: "{bold}-e{/bold} -> SrcPortsClient\n{bold}-b{/bold} -> DstPortsServer\n{bold}-c{/bold} -> dstIpsClient\n{bold}-m{/bold} -> map", 
      tags: true,
      border: {
      type: 'line'
    },
    })

, map = grid.set(0, 0, 6, 6,contrib.map,{label: 'World Map'})
, bar_list = grid.set(0, 0, 6, 6, blessed.list,{
    align: "center",
    mouse: true,
    width: "50%",
    height: "50%",
    interactive:true,
    style:{
      item:{
        fg:'green'
      },
        selected:{
          bg:'blue'
        }
          },
    focused:true,
    alwaysScroll: true,
  scrollbar: {
    ch: ' ',
    inverse: true
  },
  scrollable:true,
    keys: true,
    vi: true,
    top: "center",
    left: "center"
})
, bar_one_srcPortClient = grid.set(0.5,0,3,6,contrib.stackedBar,
        { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "50%"
       , width: "50%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , barBgColor: [ 'red', 'blue', 'green' ]})
, bar_two_srcPortClient = grid.set(3.4,0,2.7,6,contrib.stackedBar,
       { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , width: "100%"
       , barBgColor: [ 'red', 'blue', 'green' ]})
, bar_one_dstPortsServer = grid.set(0.5,0,3,6,contrib.stackedBar,
        { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "50%"
       , width: "50%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , barBgColor: [ 'red', 'blue', 'green' ]})
, bar_two_dstPortsServer = grid.set(3.5,0,2.7,6,contrib.stackedBar,
       { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , width: "100%"
       , barBgColor: [ 'red', 'blue', 'green' ]})
, bar_one_dstIPsClient = grid.set(0.5,0,3,6,contrib.stackedBar,
        { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "50%"
       , width: "50%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , barBgColor: [ 'red', 'blue', 'green' ]})
, bar_two_dstIPsClient = grid.set(3.5,0,2.7,6,contrib.stackedBar,
       { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , width: "100%"
       , barBgColor: [ 'red', 'blue', 'green' ]})
, box_bar_state = grid.set(0, 0, 0.5, 6, blessed.box,
      {top: 'center',
      left: 'center',
      width: '50%',
      style:{
         focus: {
      border:{ fg:'magenta'}
    }},
      height: '50%',
      tags: true,
      border: {
      type: 'line'
    },
    })
, bar_one_dstPortClient = grid.set(0.5,0,3,6,contrib.stackedBar,
        { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , width: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , barBgColor: [ 'green' ]})
, bar_two_dstPortClient = grid.set(3.5,0,2.6,6,contrib.stackedBar,
       { parent:bar_list
        , barWidth: 6
       , barSpacing: 10
       , xOffset: 2
       , height: "100%"
       , style:{
         focus: {
      border:{ fg:'magenta'}
    }}
       , width: "100%"
       , barBgColor: [ 'green' ]})
bar_list.hide()
box_bar_state.hide()
bar_two_dstPortClient.hide()
bar_one_dstPortClient.hide()
bar_one_dstPortsServer.hide()
bar_two_dstPortsServer.hide()

bar_one_srcPortClient.hide()
bar_two_srcPortClient.hide()

bar_one_dstIPsClient.hide()   
bar_two_dstIPsClient.hide()
map.hide()

var number_bars = Math.floor((2*bar_two_srcPortClient.width-2*bar_two_srcPortClient.options.xOffset)/(bar_two_srcPortClient.options.barSpacing+2*bar_two_srcPortClient.options.barWidth));

// var list_state = [bar_state_one, bar_state_two, bar_state_three,box_hotkeys_state, box_bar_state, map_state];

screen.render() 

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
function port_ip_setdata(bar, counter, data, number){
  var d = data[1]
  var values_bars = []
  bar.clear()
  async.each(d, function(value, callback){
    var row = []
    row.push(value)
    values_bars.push(row)
    callback()
  }, function(err){
    if(err){
      console.log('sds')
    }
    else{
      // bar.setLabel({text:Object..green,side:'left'})
      bar.setData(
      { barCategory:'seblaspijaosd'                                                                       //data[0].slice(counter,counter+number)
      , stackedCategory: ['Number of connections']
      , data: values_bars.slice(counter,counter+number)})

    }
  })

};

//function to fill in data for a box (box displays the state of the bar)
function set_box_bar_dstPortClient_state(bar_data, bar_data_two,bar_one,bar_two){
  if(bar_data[0].length > number_bars && bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Bars are scrollable. -Tab to change bars. -Left and -Right to  scroll.');
    bar_one.focus();}
  else if(bar_data[0].length > number_bars){
    box_bar_state.setContent('Upper bar is scrollable. -Left and -Right to  scroll.');
    bar_one.focus();}
  else if(bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Lower bar is scrollable. -Left and -Right to  scroll.');
    bar_two.focus();}
  else{box_bar_state.setContent('Bars are not scrollable.')
  bar_one.focus()};
  
}


//function to fill in data for a box (box displays the state of the bar)
function set_box_bar_state(bar_data, bar_data_two,bar_one,bar_two,number_bars){
  if(bar_data[0].length > number_bars && bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Bars are scrollable. -Tab to change bars. -Left and -Right to  scroll. {bold}Logarithmic scale.{/bold}');
    bar_one.focus();}
  else if(bar_data[0].length > number_bars){
    box_bar_state.setContent('Upper bar is scrollable. -Left and -Right to  scroll. {bold}Logarithmic scale.{/bold}');
    bar_one.focus();}
  else if(bar_data_two[0].length > number_bars){
    box_bar_state.setContent('Lower bar is scrollable. -Left and -Right to  scroll. {bold}Logarithmic scale.{/bold}');
    bar_two.focus();}
  else{box_bar_state.setContent('Bars are not scrollable. {bold}Logarithmic scale.{/bold}')
  bar_one.focus()};
  bar_one.show();
  bar_two.show();
  box_bar_state.show();
}

//function to fill data about destIpsCLient
function port_ips_bars(key, key2,reply){
  
  var data_dict = {};
  try{
        var obj_port = JSON.parse(reply[key]);
      var keys_port = Object.keys(obj_port);
    }
  catch(err){
        var obj_port = [];
        var keys_port = [];
      }
  async.each(keys_port, function(port, callback) {  
    var port_info = obj_port[port];
    var row = []
    // row.push(Object.values(port_info['dstips']))
    data_dict['TCP'+port] = [Object.keys(port_info['dstips']), Object.values(port_info['dstips'])]
    callback();
  }, function(err){
    if(err){
      console.log('sasdfsaa')
    }
    else{
      try{
            var obj_port = JSON.parse(reply[key2]);
          var keys_port = Object.keys(obj_port);
        }
      catch(err){
            var obj_port = [];  
            var keys_port = [];
          }
      async.each(keys_port, function(port, callback) {
        var port_info = obj_port[port];
        var row = []
    // row.push(Object.values(port_info['dstips']))
        data_dict['UDP'+port] = [Object.keys(port_info['dstips']),Object.values(port_info['dstips'])]
        callback();
      }, function(err){
        if(err){
          console.log('sasdfsaa')
        }
      });

    }
  });
return data_dict;
};


//function to fill data about destIpsCLient
function ip_tcp_bars(key, key2,reply){
  var bar_category_ips = [];
  var data_stacked_bar = [];
  try{
        var obj_ip = JSON.parse(reply[key]);
      var keys_ip = Object.keys(obj_ip);
    }
  catch(err){
        var obj_ip = [];
        var keys_ip = [];
      }
  async.each(keys_ip, function(ip, callback) {
    bar_category_ips.push('TCP/'+ip);
    var ip_info = obj_ip[ip];
    var row = [];
    row.push(ip_info['totalflows'],ip_info['totalpkt']);
    data_stacked_bar.push(row);
    callback();
  }, function(err){
    if(err){
      console.log('sasdfsaa')
    }
    else{
      try{
            var obj_ip = JSON.parse(reply[key2]);
          var keys_ip = Object.keys(obj_ip);
        }
      catch(err){
            var obj_ip = [];  
            var keys_ip = [];
          }
      async.each(keys_ip, function(ip, callback) {
        bar_category_ips.push('TCP/'+ip);
        var ip_info = obj_ip[ip];
        var row = [];
        row.push(ip_info['totalflows'],ip_info['totalpkt']);
        data_stacked_bar.push(row);
        callback();
      }, function(err){
        if(err){
          console.log('sasdfsaa')
        }
      });

    }
  });
return [data_stacked_bar, bar_category_ips]
};

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
      
      var bar_categories_protocol_port  = []
      var data_stacked_bar = []
  try{
      var obj_tcp = JSON.parse(reply[key]);
    var keys_tcp = Object.keys(obj_tcp);
  }
    catch(err){
   
      var obj_tcp =[]
      var keys_tcp = []

    }

  async.each(keys_tcp, function(key_TCP_est, callback) {
    bar_categories_protocol_port.push('TCP/'+key_TCP_est);
    var service_info = obj_tcp[key_TCP_est];
    var row = [];
    row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
    data_stacked_bar.push(row);
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
    bar_categories_protocol_port.push('UDP/'+key_UDP_est);
    var service_info = obj_udp[key_UDP_est];
    var row = [];
    row.push(round(Math.log(service_info['totalflows']),0), round(Math.log(service_info['totalpkt']),0), round(Math.log(service_info['totalbytes']),0));
    data_stacked_bar.push(row);
    callback()
    }, function(err) {
      if( err ) {
        console.log('unable to create user');
      }
    });
  }

});
return [data_stacked_bar,bar_categories_protocol_port]}

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
  var ip_info_str = "";
  var ip_info_dict = {'asn':'', 'geocountry':'', 'VirusTotal':''}

    redis_timeline_ip.hget("IPsInfo",ip,(err,reply)=>{

    try{
      var ip_info_string = '';
      var obj = JSON.parse(reply);
      var ip_values =  Object.values(obj);
      var ip_keys = Object.keys(obj);

      if(ip_keys.includes('VirusTotal')){
          var vt = obj['VirusTotal'];
          var vt_string ='VirusTotal : URL : ' + round(vt['URL'],5)+', down_file : ' + round(vt['down_file'],5)  + ', ref_file : '+ round(vt['ref_file'],5) + ', com_file : ' + round(vt['com_file'],5); 
         ip_info_dict['VirusTotal'] = vt_string;
      }
      else{ip_info_dict['VirusTotal'] = ' '}

      if(ip_keys.includes('asn')){
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
        var len_geocountry = obj['geocountry'].length;
        if(len_geocountry > 33){
        ip_info_dict['geocountry'] = obj['geocountry'].slice(0,33);}
        else{
          var rep = 33 - len_geocountry;
          ip_info_dict['geocountry'] = obj['geocountry']+" ".repeat(rep)
        }
      }
      else{ip_info_dict['geocountry'] = ' '.repeat(33);}
      
      if(mode == 1){
        ip_info_str = Object.values(ip_info_dict).join("|")
        box_ip.setContent(ip_info_str);
        screen.render();}
    }
    catch (err){
      // console.log(err)
      if(mode ==1){
        ip_info_str = " ".repeat(33) + "|"+" ".repeat(33) + "|"+" ".repeat(33)
        box_ip.setContent(ip_info_str);
        screen.render();}
      }

      })
};

function getEvidence(reply){
  /*
  retrieves IPsInfo from redis.
  */
  var ev = ''
  try{
    var obj = JSON.parse(reply);
    var keys = Object.keys(obj);
    async.each(keys, (key,callback)=>{
      ev = ev+'{bold}'+key.green+'{/bold}'+" "+obj[key]+'\n'
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

function set_tree_data(timewindows_list){
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
          for(i=0;i<ips_with_profiles.length;i++){
            var tw = timewindows_list[ips_with_profiles[i]];
            child = ips_with_profiles[i];
            result[child] = { name: child, extended:false, children: tw[0]};
            }
        }else
        result = self.childrenContent;
      } catch (e){}
      return result;
    }
}
return explorer;};

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
      .then(tree.setData(set_tree_data(ips_with_timewindows)))
      .then(screen.render());
}

redis_tree.keys('*', (err,reply)=>{
    timewindows_promises(reply);
})        
var timeline_reply_global  = {};
tree.on('select',function(node){

    if(!node.name.includes('timewindow')){
      getIpInfo_box_ip(node.name, 1)}
      
    else{
      //get infor about outtuples of a selected timeline
      redis_outtuples_timewindow.hgetall("profile_"+node.parent.name+"_"+node.name, (err,reply)=>{
        var ips = [];

        timeline_reply_global = reply;
        map.innerMap.draw(null);
        if(reply == null){
          table_outTuples.setData({headers: [''], data: []});
          box_detections.setContent('');
          return;}
        box_detections.setContent(reply['Detections']);
        getEvidence(reply['Evidence']);
        
        var obj_outTuples = JSON.parse(reply["OutTuples"]);
        var keys = Object.keys(obj_outTuples);
        var data = [];

        async.each(keys, function(key,callback){
          var row = [];
          var tuple_info = obj_outTuples[key];
          var outTuple_ip = key.split(':')[0];
          ips.push(outTuple_ip);
          
          row.push(outTuple_ip,tuple_info[0].trim());
          data.push(row)
          callback(null);

        },function(err) {
      if( err ) {
        console.log('unable to create user');
      } else {
        table_outTuples.setData({headers: [''], data: data.sort(function (a,b){return b[1].length - a[1].length})});
        setMap(ips)
      screen.render();  
      }
      });
    })}

var bar_state_one = true;
var bar_state_two = true; 
var bar_state_three = true;
var bar_state_four = true;
var box_hotkeys_state = true;
var map_state = true;
var box_hotkeys_state = true;
  screen.key('e', function(ch, key) {
    
    // console.log('i am inside  e key')
    box_bar_state.hide();
    bar_one_srcPortClient.hide()
    bar_two_srcPortClient.hide()
    bar_one_dstIPsClient.hide()
    bar_two_dstIPsClient.hide()
    bar_one_dstPortsServer.hide()
    bar_two_dstPortsServer.hide()
    bar_one_dstPortClient.hide()
    bar_two_dstPortClient.hide()
    map.hide();
    box_hotkeys.hide()
    
    // bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    box_hotkeys_state = true;
    map_state = true;
    var first_bar_counter = 0;
    var second_bar_counter = 0;
    bar_one_srcPortClient.options.barSpacing = 10;
    bar_two_srcPortClient.options.barSpacing = 10;
    if(bar_state_one){
      var est_connections_srcPortsClient = tcp_udp_connections("SrcPortsClientTCPEstablished","SrcPortsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_srcPortsClient = tcp_udp_connections("SrcPortsClientTCPNotEstablished","SrcPortsClientUDPNotEstablished",timeline_reply_global);
      var est_bar_number_srcPortsClient = Math.ceil(est_connections_srcPortsClient[0].length / number_bars);
      var notEst_bar_number_srcPortsClient = Math.ceil(notEst_connections_srcPortsClient[0].length /number_bars);
      set_box_bar_state(est_connections_srcPortsClient,notEst_connections_srcPortsClient, bar_one_srcPortClient, bar_two_srcPortClient);
      bar_setdata(bar_one_srcPortClient, first_bar_counter,est_connections_srcPortsClient, number_bars);
      bar_setdata(bar_two_srcPortClient, second_bar_counter, notEst_connections_srcPortsClient, number_bars);
      bar_one_srcPortClient.setLabel({text:'SrcPortsClientEstablished'.green,side:'left'});
      bar_two_srcPortClient.setLabel({text:'SrcPortsClientNotEstablished'.green,side:'left'});
      screen.render();


      screen.key('right', function(ch, key) {
        if(bar_one_srcPortClient.focused == true){
            if(first_bar_counter >= (est_bar_number_srcPortsClient - 1)*number_bars);
            else{
            first_bar_counter += number_bars;             
              bar_setdata(bar_one_srcPortClient, first_bar_counter, est_connections_srcPortsClient, number_bars);}}
          else{
            if(second_bar_counter >= (notEst_bar_number_srcPortsClient - 1)*number_bars); 
            else {
              second_bar_counter += number_bars;
              bar_setdata(bar_two_srcPortClient, second_bar_counter, notEst_connections_srcPortsClient, number_bars);}
          }
        screen.render()
    });
      screen.key('left', function(ch, key) {
        if(bar_one_srcPortClient.focused == true){
            first_bar_counter -=number_bars;
            if(first_bar_counter<0)first_bar_counter=0;
            bar_setdata(bar_one_srcPortClient, first_bar_counter, est_connections_srcPortsClient, number_bars);}
          else{
            second_bar_counter -= number_bars;
            if(second_bar_counter<0)second_bar_counter=0;
            bar_setdata(bar_two_srcPortClient, second_bar_counter, notEst_connections_srcPortsClient, number_bars);
          }
        screen.render()
      });

    }
    else{
    bar_list.hide()

        bar_one_srcPortClient.hide()
      bar_two_srcPortClient.hide()
        box_bar_state.hide();
      }
      bar_state_one = !bar_state_one;
      screen.render()
  
});


//display two bars of dstPortsServer established and non established connections

  screen.key('b', function(ch, key) {
    bar_list.show()
    bar_one_srcPortClient.hide()
    bar_two_srcPortClient.hide()
    bar_one_dstIPsClient.hide()
    bar_two_dstIPsClient.hide()
    bar_one_dstPortClient.hide()
    bar_two_dstPortClient.hide()
    // bar_one_dstPortsServer.hide()
    // bar_two_dstPortsServer.hide()
    map.hide();
    box_hotkeys.hide()
    // state_handle(list_state, 'bar_state_two')
    bar_state_one = true;

    // bar_state_two = true;  
    bar_state_three = true;
    bar_state_four = true;
    box_hotkeys_state = true;
    map_state = true;
    var first_bar_counter = 0;
    var second_bar_counter = 0;
    bar_two_dstPortsServer.options.barSpacing = 10;
    bar_one_dstPortsServer.options.barSpacing = 10;
    if(bar_state_two){
      var est_connections_dstPortsServer = tcp_udp_connections("DstPortsServerTCPEstablished","DstPortsServerUDPEstablished",timeline_reply_global);
      var notEst_connections_dstPortsServer = tcp_udp_connections("DstPortsServerTCPNotEstablished","DstPortsServerUDPNotEstablished",timeline_reply_global);
      var est_bar_number_dstPortsServer = Math.ceil(est_connections_dstPortsServer[0].length / number_bars);
      var notEst_bar_number_dstPortsServer = Math.ceil(notEst_connections_dstPortsServer[0].length /number_bars);
      set_box_bar_state(est_connections_dstPortsServer,notEst_connections_dstPortsServer,bar_one_dstPortsServer,bar_two_dstPortsServer)
      bar_setdata(bar_one_dstPortsServer, first_bar_counter,est_connections_dstPortsServer, number_bars);
      bar_setdata(bar_two_dstPortsServer, second_bar_counter, notEst_connections_dstPortsServer, number_bars);
      bar_one_dstPortsServer.setLabel({text:'DstPortsServerEstablished'.green,side:'left'});
      bar_two_dstPortsServer.setLabel({text:'DstPortsServerNotEstablished'.green,side:'left'});
      screen.render();
      screen.key('right', function(ch, key) {
        if(bar_one_dstPortsServer.focused == true){

            if(first_bar_counter >= (est_bar_number_dstPortsServer-1)*number_bars);
            else{
            first_bar_counter += number_bars;             
              bar_setdata(bar_one_dstPortsServer, first_bar_counter, est_connections_dstPortsServer,number_bars);}}
          else{
            if(second_bar_counter >= (notEst_bar_number_dstPortsServer-1)*number_bars); 
            else {
              second_bar_counter += number_bars;
              bar_setdata(bar_two_dstPortsServer, second_bar_counter, notEst_connections_dstPortsServer, number_bars);}
          }
        screen.render()
    });
      screen.key('left', function(ch, key) {
        if(bar_one_dstPortsServer.focused == true){
            first_bar_counter -=number_bars;
            if(first_bar_counter<0)first_bar_counter=0;
            bar_setdata(bar_one_dstPortsServer, first_bar_counter, est_connections_dstPortsServer,number_bars);}
          else{
            second_bar_counter -= number_bars;
            if(second_bar_counter<0)second_bar_counter=0;
            bar_setdata(bar_two_dstPortsServer, second_bar_counter, notEst_connections_dstPortsServer,number_bars);
          }
        screen.render()
      });

    }
    else{
    bar_list.hide()

        bar_one_dstPortsServer.hide();
        bar_two_dstPortsServer.hide();
        box_bar_state.hide();
      }
      bar_state_two= !bar_state_two;
      screen.render()
  
});

//display to bars of dstIPsClient established and non established connections
  screen.key('c', function(ch, key) {
    bar_one_srcPortClient.hide()
    bar_two_srcPortClient.hide()
    // bar_one_dstIPsClient.hide()
    // bar_two_dstIPsClient.hide()
    bar_one_dstPortsServer.hide()
    bar_two_dstPortsServer.hide()
    bar_one_dstPortClient.hide()
    bar_two_dstPortClient.hide()
    // box_bar_state.hide();
    map.hide();

    box_hotkeys.hide()
    bar_list.show()
    // state_handle(list_state, 'bar_state_three');
    bar_state_one = true;
    bar_state_two = true; 
    // bar_state_three = true;
    bar_state_four = true;
    box_hotkeys_state = true;
    map_state = true;
    var first_bar_counter = 0;
    var second_bar_counter = 0;
    bar_one_dstIPsClient.options.barSpacing = 25;
    bar_two_dstIPsClient.options.barSpacing = 25;
    if(bar_state_three){
      var number_bars_ips = 5
      var est_connections_ips = tcp_udp_connections("DstIPsClientTCPEstablished","DstIPsClientUDPEstablished",timeline_reply_global);
      var notEst_connections_ips= tcp_udp_connections("DstIPsClientTCPNotEstablished","DstIPsClientUDPNotEstablished",timeline_reply_global);
      var est_ips_bar_number = Math.ceil(est_connections_ips[0].length / number_bars_ips);
      var notEst_ips_bar_number = Math.ceil(notEst_connections_ips[0].length /number_bars_ips);
      set_box_bar_state(est_connections_ips,notEst_connections_ips,bar_one_dstIPsClient,bar_two_dstIPsClient)

      bar_setdata(bar_one_dstIPsClient, first_bar_counter,est_connections_ips,number_bars_ips);
      bar_setdata(bar_two_dstIPsClient, second_bar_counter, notEst_connections_ips,number_bars_ips);
      bar_one_dstIPsClient.setLabel({text:'DstIPsClientEstablished'.green,side:'left'});
      bar_two_dstIPsClient.setLabel({text:'DstIPsClientNotEstablished'.green,side:'left'});
      screen.render();
      screen.key('right', function(ch, key) {
        if(bar_one_dstIPsClient.focused == true){

            if(first_bar_counter >= (est_ips_bar_number-1)*number_bars_ips);
            else{
            first_bar_counter += number_bars_ips;             
              bar_setdata(bar_one_dstIPsClient, first_bar_counter, est_connections_ips,number_bars_ips);}}
          else{
            if(second_bar_counter >= (notEst_ips_bar_number-1)*number_bars_ips); 
            else {
              second_bar_counter += number_bars_ips;
              bar_setdata(bar_two_dstIPsClient, second_bar_counter, notEst_connections_ips,number_bars_ips);}
          }
        screen.render()
    });
      screen.key('left', function(ch, key) {
        if(bar_one_dstIPsClient.focused == true){
            first_bar_counter -= number_bars_ips;
            if(first_bar_counter<0)first_bar_counter=0;
            bar_setdata(bar_one_dstIPsClient, first_bar_counter, est_connections_ips,number_bars_ips);}
          else{
            second_bar_counter -= number_bars_ips;
            if(second_bar_counter<0)second_bar_counter=0;
            bar_setdata(bar_two_dstIPsClient, second_bar_counter, notEst_connections_ips,number_bars_ips);
          }
        screen.render()
      });

    }
    else{
      bar_list.hide()

        bar_one_dstIPsClient.hide();
        bar_two_dstIPsClient.hide();
        box_bar_state.hide();
      }
      bar_state_three = !bar_state_three;
      screen.render();
  
});


screen.key('v', function(ch, key) {
    
    // box_bar_state.hide();
    bar_one_srcPortClient.hide()
    bar_two_srcPortClient.hide()
    bar_one_dstIPsClient.hide()
    bar_two_dstIPsClient.hide()
    bar_one_dstPortsServer.hide()
    bar_two_dstPortsServer.hide()
    map.hide();
    box_hotkeys.hide()
    bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    
    box_hotkeys_state = true;
    map_state = true;
    var first_bar_counter = 0;
    var second_bar_counter = 0;
    var vertical_counter = 0;
    bar_one_dstPortClient.options.barSpacing = 25;
    bar_two_dstPortClient.options.barSpacing = 25;
    if(bar_state_four){
      try{
      number_bars = 5
      var est_connections_dstPortsClient = port_ips_bars("DstPortsClientTCPEstablished","DstPortsClientUDPEstablished",timeline_reply_global);
      var dstPortsClient_keys = Object.keys(est_connections_dstPortsClient);
      var dstPortsClient_values = Object.values(est_connections_dstPortsClient);
      var est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
      var est_bar_two_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter+1][0].length / number_bars);
      var vertical = Math.ceil(dstPortsClient_keys.length / 2);
      port_ip_setdata(bar_one_dstPortClient, first_bar_counter, dstPortsClient_values[vertical_counter], number_bars);
      port_ip_setdata(bar_two_dstPortClient, second_bar_counter, dstPortsClient_values[vertical_counter+1], number_bars);
      // set_box_bar_dstPortClient_state(dstPortsClient_values[vertical_counter][0],dstPortsClient_values[vertical_counter+1][0], bar_one_dstPortClient, bar_two_dstPortClient, number_bars)
      bar_one_dstPortClient.setLabel({text:dstPortsClient_keys[0].green,side:'left'});
      bar_two_dstPortClient.setLabel({text:dstPortsClient_keys[1].green,side:'left'});
      bar_one_dstPortClient.show();
      bar_list.show()
      bar_two_dstPortClient.show();
      box_bar_state.show();
      bar_one_dstPortClient.focus();
      // bar_two_srcPortClient.setLabel({text:'DstPortsClientNotEstablished'.green,side:'left'});
      screen.render();


      screen.key('right', function(ch, key) {
        
        if(bar_one_dstPortClient.focused == true){
            if(first_bar_counter >= (est_bar_one_number_dstPortsClient-1)*number_bars);
            else{
            first_bar_counter += number_bars;             
              port_ip_setdata(bar_one_dstPortClient, first_bar_counter, dstPortsClient_values[vertical_counter], number_bars);}}
          else{
            if(second_bar_counter >= (est_bar_two_number_dstPortsClient-1)*number_bars); 
            else {
              second_bar_counter += 5;
              port_ip_setdata(bar_two_dstPortClient, second_bar_counter, dstPortsClient_values[vertical_counter+1], number_bars);}
          }
        screen.render()
    });
      screen.key('left', function(ch, key) {
        if(bar_one_dstPortClient.focused == true){
            first_bar_counter -=number_bars;
            if(first_bar_counter<0)first_bar_counter=0;
            port_ip_setdata(bar_one_dstPortClient, first_bar_counter, dstPortsClient_values[vertical_counter], number_bars);}
          else{
            second_bar_counter -= number_bars;
            if(second_bar_counter<0)second_bar_counter=0;
            port_ip_setdata(bar_two_dstPortClient, second_bar_counter,dstPortsClient_values[vertical_counter+1], number_bars);
          }
        screen.render()
      });
      screen.key('down', function(ch, key) {
          vertical_counter +=2;
          if(vertical_counter > (vertical-1)*2){vertical_counter -=2;}
          else{
            if(dstPortsClient_keys[vertical_counter]===undefined){
              bar_one_dstPortClient.clear();
              bar_one_dstPortClient.setLabel({text:'empty'.green,side:'left'})
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:'empty'.green,side:'left'})
            }
            else if(dstPortsClient_keys[vertical_counter+1]===undefined){
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:dstPortsClient_keys[vertical_counter].green,side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:'empty'.green,side:'left'})
            }
            else{
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              est_bar_two_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter+1][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:dstPortsClient_keys[vertical_counter].green,side:'left'});
              bar_two_dstPortClient.setLabel({text:dstPortsClient_keys[vertical_counter+1].green,side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              port_ip_setdata(bar_two_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter+1], number_bars);
              // set_box_bar_dstPortClient_state(dstPortsClient_values[vertical_counter][0],dstPortsClient_values[vertical_counter+1][0], bar_one_dstPortClient, bar_two_dstPortClient, number_bars);
            }}
          
        screen.render()
      });
      screen.key('up', function(ch, key) {
          vertical_counter -=2;
          if(vertical_counter <0){vertical_counter =0;}
          else{
            if(dstPortsClient_keys[vertical_counter]===undefined){
              bar_one_dstPortClient.clear();
              bar_one_dstPortClient.setLabel({text:'empty'.green,side:'left'})
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:'empty'.green,side:'left'})
            }
            else if(dstPortsClient_keys[vertical_counter+1]===undefined){
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:dstPortsClient_keys[vertical_counter].green,side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              bar_two_dstPortClient.clear();
              bar_two_dstPortClient.setLabel({text:'empty'.green,side:'left'})
            }
            else{
              est_bar_one_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter][0].length / number_bars);
              est_bar_two_number_dstPortsClient = Math.ceil(dstPortsClient_values[vertical_counter+1][0].length / number_bars);
              bar_one_dstPortClient.setLabel({text:dstPortsClient_keys[vertical_counter].green,side:'left'});
              bar_two_dstPortClient.setLabel({text:dstPortsClient_keys[vertical_counter+1].green,side:'left'});
              port_ip_setdata(bar_one_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter], number_bars);
              port_ip_setdata(bar_two_dstPortClient, 0, Object.values(est_connections_dstPortsClient)[vertical_counter+1], number_bars);
            // set_box_bar_dstPortClient_state(dstPortsClient_values[vertical_counter][0],dstPortsClient_values[vertical_counter+1][0], bar_one_dstPortClient, bar_two_dstPortClient, number_bars);
          }}
          
        screen.render()
      });

    }catch(err){
      box_bar_state.setContent('no information')
      bar_list.show()
      // bar_one_dstPortClient.clear()
    //    bar_two_dstPortClient.clear()
    //    bar_one_dstPortClient.show()

      // bar_two_dstPortClient.show()
        box_bar_state.show()}}
    else{
      
      bar_list.hide()

        bar_one_dstPortClient.hide()
      bar_two_dstPortClient.hide()
        box_bar_state.hide();
      }
      bar_state_four = !bar_state_four;
      screen.render()
  
});
// 
    //get the timeline of a selected ip
    redis_get_timeline.lrange("profile_"+node.parent.name+"_"+node.name+'_timeline',0,-1, (err,reply)=>{
      var data = [];
      async.each(reply, function(line, callback){
        var row = [];
        var line_arr = line.split(" ")
        var index_to = line_arr.indexOf('to')
        var index_asked = line_arr.indexOf('asked');
        var index_careful = line_arr.indexOf('careful!');
        var index_recognized = line_arr.indexOf('recognized');
        var index_ip = index_to +1;
        if(index_to>= 0 && line_arr[index_ip].length>6)line_arr[index_ip]= "{bold}"+line_arr[index_ip]+"{/bold}"
        
        if(index_recognized >= 0){
          for(var i =index_recognized - 10; i < index_recognized+3;i++){
          line_arr[i] = line_arr[i].red;}
          }

        if(index_careful > 0){
          line_arr[index_careful] = line_arr[index_careful].red;
          line_arr[index_careful - 1] = line_arr[index_careful - 1].red
        }
        for(var i =3; i < index_asked;i++){
          line_arr[i] = line_arr[i].bold.cyan }     
        if(line_arr[index_to+2].includes('/'))line_arr[index_to+2]=line_arr[index_to+2].slice(0,-1).bold.yellow+','
        line_arr[1]= line_arr[1].substring(0, line_arr[1].lastIndexOf('.'));
        timeline_line = line_arr.join(" ");
        row.push(timeline_line.replace(/\|.*/,''));
        data.push(row);
        callback();
      },function(err) {
        if( err ) {
          console.log('unable to create user');
        } else {
          table_timeline.setData({headers:[node.parent.name+" "+node.name], data: data});
          screen.render();}
    });
  })

     
  screen.key('m', function(ch, key) {
    bar_one_srcPortClient.hide()
    bar_two_srcPortClient.hide()
    bar_one_dstIPsClient.hide()
    bar_two_dstIPsClient.hide()
    bar_one_dstPortsServer.hide()
    bar_two_dstPortsServer.hide()
    bar_one_dstPortClient.hide()
    bar_two_dstPortClient.hide()
    bar_list.hide()
    
    box_bar_state.hide();
    // map.hide();
    box_hotkeys.hide()
    bar_state_one = true;
    bar_state_two = true; 
    bar_state_three = true;
    bar_state_four = true;
    box_hotkeys_state = true;
    // map_state = true;

    if(map_state){
      map.show()
    }
    else{
        map.hide()  
      }
      map_state = !map_state;
      screen.render()
  
});
   })
//     }
// });
table_timeline.rows.on('select', (item, index) => {
  var timeline_line = item.content.split(" ");
  var index_to = timeline_line.indexOf('to')
  var timeline_ip = timeline_line[index_to +1].slice(6,-7)
  getIpInfo_box_ip(timeline_ip,1)
});

table_outTuples.rows.on('select', (item, index) => {
  var outTuple_ip = item.content.trim().split(":")[0]
  getIpInfo_box_ip(outTuple_ip,1)

});

box_hotkeys.hide();

screen.key('h', function(ch, key) {
  bar_one_srcPortClient.hide()
    bar_two_srcPortClient.hide()
    bar_one_dstIPsClient.hide()
    bar_two_dstIPsClient.hide()
    bar_one_dstPortsServer.hide()
    bar_two_dstPortsServer.hide()
  // bar_two.hide();
  box_bar_state.hide();
  map.hide();
  // box_hotkeys.hide()
  bar_state_one = true;
  bar_state_two = true; 
  bar_state_three = true;
  bar_state_four = true;
  // box_hotkeys_state = true;
  map_state = true;
  if(box_hotkeys_state){
    box_hotkeys.show()
  }
  else{box_hotkeys.hide()}
    box_hotkeys_state =! box_hotkeys_state
  screen.render();
});


screen.key(['tab'], function(ch, key) {
  if(bar_one_srcPortClient.focused == true){
      bar_two_srcPortClient.focus();}
  else if(bar_two_srcPortClient.focused == true)
    {bar_one_srcPortClient.focus();}
  else if(bar_one_dstIPsClient.focused == true){
      bar_two_dstIPsClient.focus();}
  else if(bar_two_dstIPsClient.focused == true)
    {bar_one_dstIPsClient.focus();}
  else if(bar_one_dstIPsClient.focused == true){
      bar_two_dstPortsServer.focus();}
  else if(bar_two_dstIPsClient.focused == true)
    {bar_one_dstIPsClient.focus();}
  else if(bar_one_dstPortClient.focused == true){
      bar_two_dstPortClient.focus();}
  else if(bar_two_dstPortClient.focused == true)
    {bar_one_dstPortClient.focus();}
  else if(screen.focused == tree.rows){
    tree.style.border.fg = 'blue'
    table_timeline.style.border.fg='magenta'
    table_timeline.focus();}
  else if(screen.focused == table_timeline.rows){
    table_timeline.style.border.fg='blue'
    table_outTuples.style.border.fg='magenta'
    table_outTuples.focus();}
  else if(screen.focused == table_outTuples.rows){
    table_outTuples.style.border.fg='blue'
    box_detections.focus()}
  else if(screen.focused == box_detections){
    box_evidence.focus()}
  else{
    tree.style.border.fg = 'magenta'
    tree.focus();}
    screen.render()})

screen.key(['S-tab'], function(ch, key) {
  // if(bar_one_srcPortClient.focused == true){
  //     bar_two_srcPortClient.focus();}
  // else if(bar_two_srcPortClient.focused == true)
  //   {bar_one_srcPortClient.focus();}
  // else if(bar_one_dstIPsClient.focused == true){
  //     bar_two_dstIPsClient.focus();}
  // else if(bar_two_dstIPsClient.focused == true)
  //   {bar_one_dstIPsClient.focus();}
  // else if(bar_one_dstIPsClient.focused == true){
  //     bar_two_dstPortsServer.focus();}
  // else if(bar_two_dstIPsClient.focused == true)
  //   {bar_one_dstIPsClient.focus();}

  // else if(bar_one_dstPortClient.focused == true){
  //     bar_two_dstPortClient.focus();}
  // else if(bar_two_dstPortClient.focused == true)
  //   {bar_one_dstPortClient.focus();}

  if(screen.focused == table_timeline.rows){
    table_timeline.style.border.fg = 'blue'
    tree.style.border.fg='magenta'
    tree.focus();}
  else if(screen.focused == table_outTuples.rows){
    table_outTuples.style.border.fg='blue'
    table_timeline.style.border.fg='magenta'
    table_timeline.focus();}
  else if(screen.focused == box_detections){
    table_outTuples.style.border.fg='magenta'
    table_outTuples.focus()}
  else if(screen.focused == box_evidence){
    box_detections.focus()}
  else{
    tree.style.border.fg = 'blue'
    box_evidence.focus();}
   
screen.render();
});
tree.focus();
// screen.on('resize', function() {
//   tree.emit('attach');
//   table_timeline.emit('attach');
//   table_outTuples.emit('attach');
//   box_detections.emit('attach');
//   box_evidence.emit('attach');
//   box_ip.emit('attach');
//   box_hotkeys.emit('attach');
//   map.emit('attach');
//   bar_two.emit('attach');
//   bar_one.emit('attach');0
// });
screen.key(["escape", "q", "C-c"], function(ch, key) {
    return process.exit(0);
});
screen.render();
