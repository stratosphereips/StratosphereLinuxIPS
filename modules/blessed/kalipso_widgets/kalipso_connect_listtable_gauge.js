var async = require('async')

class combine_Listtable_Gauge{

  constructor(grid, blessed, contrib, redis_database,screen, listtable1, listtable2, gauge1, gauge2){
        this.contrib = contrib
        this.screen = screen
        this.blessed = blessed
        this.grid = grid
        this.redis_database = redis_database
        this.listtable1 = listtable1
        this.listtable2 = listtable2
        this.gauge1 = gauge1
        this.gauge2 = gauge2
  }

  round(value, decimals) {
    /*
    Function to round numbers to 3 decimals points
    */
    return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
  };

  format_tcp_udp_data_with_IPs(redis_data, tcp_or_udp){
   /*
    This data includes IP as a column value
    Function to refactor tcp and udp data from profile's timewindow for specific widgets listtables and gauges.
    Format of data for listtable: [[column1,column2,column3],[column1,column2,column3],[column1,column2,column3]]
    Format of data for stack: [{stack:[percent%,percent2%,percent3%]},{stack:[percent%,percent2%,percent3%]},{stack:[percent%,percent2%,percent3%]}]
    */
    return new Promise((resolve, reject)=>{
      var data_listtable = [];
      var data_gaugeList = [];
      if(redis_data == null){resolve([data_listtable, data_gaugeList])}
      else{ 
      try{
        var obj= JSON.parse(redis_data);
        var keys = Object.keys(obj);
      async.each(keys, (key, callback)=>{
        var key_info = obj[key];
        var dst_ips = Object.keys(key_info['dstips'])
        var dst_ips_connections = Object.values(key_info['dstips'])
        async.forEachOf(dst_ips,(dst_ip_counter, dst_ip_index,callback)=>{
          var row = []
          data_listtable.push([tcp_or_udp+'/'+key,String(dst_ip_counter),String(dst_ips_connections[dst_ip_index])])
          data_listtable.push([])
          data_gaugeList.push({stack:[this.round(Math.log(dst_ips_connections[dst_ip_index]),0)]})
          callback()
        },(err)=>{
          if(err){console.log(err)}
        })
        callback()
      },(err)=>{
        if(err){console.log(err)}
        else{
            resolve([data_listtable,data_gaugeList])
          }
      })
    }
    catch(err){
      if(err){console.log(err)}
    }
    }
})}
        

  format_tcp_udp_data(redis_data,tcp_or_udp){
    /*
    Function to refactor tcp and udp data from profile's timewindow for specific widgets listtables and gauges.
    Format of data for listtable: [[column1,column2,column3],[column1,column2,column3],[column1,column2,column3]]
    Format of data for stack: [{stack:[percent%,percent2%,percent3%]},{stack:[percent%,percent2%,percent3%]},{stack:[percent%,percent2%,percent3%]}]
    */
    return new Promise((resolve, reject)=>{
      var data_listtable = [];
      var data_gaugeList = [];
      if(redis_data == null){resolve([data_listtable, data_gaugeList])}
      else{ 
      try{
        var obj= JSON.parse(redis_data);
        var keys = Object.keys(obj);
      async.each(keys, (key, callback)=>{
        var key_info = obj[key];
        data_listtable.push([tcp_or_udp+'/'+key,String(key_info['totalflows']), String(key_info['totalpkt']), String(key_info['totalbytes'])])
        data_listtable.push([])
        data_gaugeList.push({stack:[this.round(Math.log(key_info['totalflows']),0), this.round(Math.log(key_info['totalpkt']),0), this.round(Math.log(key_info['totalbytes']),0)]})
        callback();
      }, (err)=>{
        if(err){
          console.log(err)
          reject(err)}
        else{
          resolve([data_listtable,data_gaugeList])
          }
        })}
      catch(err){if(err){console.log(err)}}
    }})
  }

  format_redis_tcp_udp_data(redis_tcp_data, redis_udp_data){
    /*
    Function to refactor in series tcp and udp data from profile's timewindow for specific widgets listtables and gauges.
    */
    return Promise.all([this.format_tcp_udp_data(redis_tcp_data, 'TCP'), this.format_tcp_udp_data(redis_udp_data, 'UDP')]).then(values=>{return values}) 
  }
  format_redis_tcp_udp_data_with_IPs(redis_tcp_data, redis_udp_data){
    /*
    Function to refactor in series tcp and udp data from profile's timewindow for specific widgets listtables and gauges.
    */
    return Promise.all([this.format_tcp_udp_data_with_IPs(redis_tcp_data, 'TCP'), this.format_tcp_udp_data_with_IPs(redis_udp_data, 'UDP')]).then(values=>{return values}) 
  }
  set_tcp_udp_data_est(ip, timewindow, TCPkey, UDPkey){
    /*
    Function to get the data from redis database for established TCP and UDP connections
    */
    return Promise.all([this.redis_database.getTCPest(ip, timewindow, TCPkey), this.redis_database.getUDPest(ip, timewindow, UDPkey)]).then(values=>{return values;})
  }
  set_tcp_udp_data_notest(ip, timewindow, TCPkey, UDPkey){
    /*
    Function to get the data from redis database for notestablished TCP and UDP connections
    */
    return Promise.all([this.redis_database.getTCPnotest(ip, timewindow, TCPkey), this.redis_database.getUDPnotest(ip, timewindow, UDPkey)]).then(values=>{return values;})
  }

  combine_tcp_udp(tcp_data, udp_data){
    /*
    Function to combine TCP and UDP data in one list separately for listtable and gauge widgets
    */
    return new Promise((resolve, reject)=>{
      // if(tcp_data == null)console.log('tcp_data')
      var tcp_data_listtable = tcp_data[0]
      var tcp_data_gauge = tcp_data[1]
      var udp_data_listtable = udp_data[0]
      var udp_data_gauge = udp_data[1]
      var final_listtable = tcp_data_listtable.concat(udp_data_listtable)
      var final_gauge = tcp_data_gauge.concat(udp_data_gauge)
      resolve([final_listtable, final_gauge])
    })
  }

  operate(ip, timewindow, TCP_key_established,  UDP_key_established, TCP_key_notestablished, UDP_key_notEstablished,listtable1_column_names,listtable2_column_names){
    /*
    Function to format TCP and UDP data for lsttable and gauges
    */
    return Promise.all(
                  [
                  this.set_tcp_udp_data_est(ip, timewindow, TCP_key_established, UDP_key_established),
                  this.set_tcp_udp_data_notest(ip, timewindow, TCP_key_notestablished, UDP_key_notEstablished)
                  ]
                  )
          .then(
          values=>{
                  Promise.all(
                              [
                              this.format_redis_tcp_udp_data(values[0][0],values[0][1]),
                              this.format_redis_tcp_udp_data(values[1][0],values[1][1])
                              ]
                              )
                  .then(
                        data=>{
                              Promise.all(
                                        [
                                        this.combine_tcp_udp(data[0][0],data[0][1]), 
                                        this.combine_tcp_udp(data[1][0], data[1][1])
                                        ]
                                        )
                              .then(
                                  val=>{
                                        this.fake_control(val[0],val[1],listtable1_column_names,listtable2_column_names)
                                        }
                                    )
                              }
                       )
                  }
          )    
  }

  operate_IPs(ip, timewindow, TCP_key_established,  UDP_key_established, TCP_key_notestablished, UDP_key_notEstablished, listtable1_column_names, listtable2_column_names){
    /*
    Function to format TCP and UDP data for lsttable and gauges when it has IP as a column value
    */
    return Promise.all(
                  [
                  this.set_tcp_udp_data_est(ip, timewindow, TCP_key_established, UDP_key_established),
                  this.set_tcp_udp_data_notest(ip, timewindow, TCP_key_notestablished, UDP_key_notEstablished)
                  ]
                  )
          .then(
          values=>{
                  Promise.all(
                              [
                              this.format_redis_tcp_udp_data_with_IPs(values[0][0],values[0][1]),
                              this.format_redis_tcp_udp_data_with_IPs(values[1][0],values[1][1])
                              ]
                              )
                  .then(
                        data=>{
                              Promise.all(
                                        [
                                        this.combine_tcp_udp(data[0][0],data[0][1]), 
                                        this.combine_tcp_udp(data[1][0], data[1][1])
                                        ]
                                        )
                              .then(
                                  val=>{
                                        this.fake_control(val[0],val[1],listtable1_column_names, listtable2_column_names)
                                        }
                                    )
                              }
                       )
                  }
          )    
  }

  fake_control(data_established, data_notestablished,listtable1_column_names,listtable2_column_names){
    /*
    Function to control the scrolling simultaneously in gauge and listtable. 
    We scroll the data in so-called 'pages'. 
    */
    var listtable1_counter = 0
    var listtable2_counter = 0
    var gauge1_counter = 0
    var gauge2_counter = 0
    var gauge_number = 9
    var total_data1 = Math.ceil(data_established[1].length / gauge_number);
    var total_data2 = Math.ceil(data_notestablished[1].length / gauge_number);
    
    var gauge1_data_sliced = data_established[1].slice(0,gauge_number)
    this.gauge1.setData(gauge1_data_sliced)
    
    var gauge2_data_sliced = data_notestablished[1].slice(0,gauge_number)
    this.gauge2.setData(gauge2_data_sliced)

    var listtable1_data_sliced = [listtable1_column_names,[],...data_established[0].slice(0,gauge_number*2)]
    this.listtable1.setData(listtable1_data_sliced)
    
    var listtable2_data_sliced =  [listtable2_column_names,[],...data_notestablished[0].slice(0,gauge_number*2)]
    this.listtable2.setData(listtable2_data_sliced)

    this.listtable1.show()
    this.listtable2.show()
    this.gauge1.show()
    this.gauge2.show()
    this.gauge1.focus()

    this.screen.render()

    this.screen.key(['down','j'], (ch,key)=>{
      if(this.gauge1.widget.focused == true){
        if(gauge1_counter >= (total_data1-1)*gauge_number);
        else{
          listtable1_counter += gauge_number*2
          gauge1_counter += gauge_number
          listtable1_data_sliced = [listtable1_column_names,[],...data_established[0].slice(listtable1_counter, listtable1_counter + gauge_number*2)]
          gauge1_data_sliced = data_established[1].slice(gauge1_counter, gauge1_counter + gauge_number)
          this.listtable1.setData(listtable1_data_sliced)
          this.gauge1.setData(gauge1_data_sliced)
          this.screen.render()
        }
      }
      else{
        if(gauge2_counter >= (total_data2-1)*gauge_number);
        else{
          listtable2_counter += gauge_number*2
          gauge2_counter += gauge_number
          listtable2_data_sliced = [listtable2_column_names,[],...data_notestablished[0].slice(listtable2_counter, listtable2_counter + gauge_number*2)]
          gauge2_data_sliced = data_notestablished[1].slice(gauge2_counter, gauge2_counter + gauge_number)
          this.listtable2.setData(listtable2_data_sliced)
          this.gauge2.setData(gauge2_data_sliced)
          this.screen.render()
        }
      }
    })
     
    this.screen.key(['up','k'],(ch,key)=>{
      if(this.gauge1.widget.focused==true){
        listtable1_counter -= gauge_number*2
        gauge1_counter -= gauge_number
        if(listtable1_counter <= 0){listtable1_counter = 0; gauge1_counter = 0;}
        listtable1_data_sliced = [listtable1_column_names,[],...data_established[0].slice(listtable1_counter, listtable1_counter + gauge_number*2)]
        gauge1_data_sliced = data_established[1].slice(gauge1_counter, gauge1_counter + gauge_number)
        this.listtable1.setData(listtable1_data_sliced)
        this.gauge1.setData(gauge1_data_sliced)
        this.screen.render()
      }
      else{
        listtable2_counter -= gauge_number*2
        gauge2_counter -= gauge_number
        if(listtable2_counter <= 0){listtable2_counter = 0; gauge2_counter = 0;}
        listtable2_data_sliced = [listtable2_column_names,[],...data_notestablished[0].slice(listtable2_counter, listtable2_counter + gauge_number*2)]
        gauge2_data_sliced = data_notestablished[1].slice(gauge2_counter, gauge2_counter + gauge_number)
        this.listtable2.setData(listtable2_data_sliced)
        this.gauge2.setData(gauge2_data_sliced)
        this.screen.render()

      }
    })

  }
}

module.exports = combine_Listtable_Gauge
