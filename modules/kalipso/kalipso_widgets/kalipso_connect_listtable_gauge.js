// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
const { redis, blessed, blessed_contrib, async, sortedArray } = require("./libraries.js");

class combine_Listtable_Gauge{
    constructor(grid,  redis_database,screen, listtable1, listtable2, gauge1, gauge2){
        this.screen = screen
        this.grid = grid
        this.redis_database = redis_database
        this.listtable1 = listtable1
        this.listtable2 = listtable2
        this.gauge1 = gauge1
        this.gauge2 = gauge2
        this.gauge1_counter = 0
        this.gauge2_counter = 0
        this.total_data1 = 0
        this.total_data2 = 0
        this.listtable1_counter = 0
        this.listtable2_counter = 0
        this.listtable1_data = []
        this.listtable2_data = []
        this.gauge1_data = []
        this.gauge2_data = []
        this.gauge_number = 9
        this.listtable1_column_names = []
        this.listtable2_column_names = []
        this.focus = this.gauge1
        }

    /*Round numbers by specific decimals*/
    round(value, decimals) {
        return Number(Math.round(value+'e'+decimals)+'e-'+decimals);
    };

    changeFocus(){
        if(this.focus == this.gauge1){
            this.focus = this.gauge2
            this.gauge2.focus()}
        else{
            this.focus = this.gauge1
            this.gauge1.focus()}
    }

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
                      data_listtable.push([tcp_or_udp+'/'+key,String(dst_ip_counter),String(dst_ips_connections[dst_ip_index]['pkts'])])
                      data_listtable.push([])
                      data_gaugeList.push({stack:[this.round(Math.log(dst_ips_connections[dst_ip_index]['pkts']),0)]})
                      callback()
                    },(err)=>{
                    if(err){console.log('Check format_tcp_udp_data_with_IPs in kalipso_connect_listtable_gauge.js. Error: ',err)}
                    })
                callback()
                },(err)=>{
                if(err){console.log('Check format_tcp_udp_data_with_IPs in kalipso_connect_listtable_gauge.js. Error: ',err)}
                else{ resolve([data_listtable,data_gaugeList])}
                })
            }
            catch(err){
            if(err){console.log('Check format_tcp_udp_data_with_IPs in kalipso_connect_listtable_gauge.js. Error: ',err)}}
        }
        })
    }


    format_tcp_udp_data(redis_data,tcp_or_udp){
    /*
    Function to refactor tcp and udp data from profile's timewindow for specific widgets listtables and gauges.
    Format of data for listtable: [[column1,column2,column3],[column1,column2,column3],[column1,column2,column3]]
    Format of data for stack: [{stack:[percent%,percent2%,percent3%]},{stack:[percent%,percent2%,percent3%]},{stack:[percent%,percent2%,percent3%]}]
    */
    return new Promise((resolve, reject)=>{
        let data_listtable = [];
        let data_gaugeList = [];
        if(redis_data == null){resolve([data_listtable, data_gaugeList])}
        else{
            try{
                let obj= JSON.parse(redis_data);
                var instance  = new sortedArray(Object.keys(obj), function(a, b){
                return obj[b]['totalbytes'] - obj[a]['totalbytes'];
                });
                instance.getArray().then(keys=>{async.each(keys, (key, callback)=>{
                    let key_info = obj[key];
                    data_listtable.push([tcp_or_udp+'/'+key,String(key_info['totalflows']), String(key_info['totalpkt']), String(key_info['totalbytes'])])
                    data_listtable.push([])
                    data_gaugeList.push({stack:[this.round(Math.log(key_info['totalflows']),0),
                                                this.round(Math.log(key_info['totalpkt']),0),
                                                this.round(Math.log(key_info['totalbytes']),0)]})
                    callback();
                    }, (err)=>{
                    if(err){console.log('Check format_tcp_udp_data in kalipso_connect_listtable_gauge.js. Error: ',err);reject(err)}
                    else{resolve([data_listtable,data_gaugeList])}
                })})
            }
            catch(err){if(err){console.log('Check format_tcp_udp_data in kalipso_connect_listtable_gauge.js. Error: ',err)}}
    }})
  }

    /*Function to refactor in series tcp and udp data from profile's timewindow for specific widgets listtables and gauges.*/
    format_redis_tcp_udp_data(redis_tcp_data, redis_udp_data){
        return Promise.all([this.format_tcp_udp_data(redis_tcp_data, 'TCP'), this.format_tcp_udp_data(redis_udp_data, 'UDP')]).then(values=>{return values})
    }

    /*Function to refactor in series tcp and udp data from profile's timewindow for specific widgets listtables and gauges.*/
    format_redis_tcp_udp_data_with_IPs(redis_tcp_data, redis_udp_data){
        return Promise.all([this.format_tcp_udp_data_with_IPs(redis_tcp_data, 'TCP'), this.format_tcp_udp_data_with_IPs(redis_udp_data, 'UDP')]).then(values=>{return values})
    }

    /*Function to get the data from redis database for established TCP and UDP connections*/
    set_tcp_udp_data_est(ip, timewindow, TCPkey, UDPkey){
        return Promise.all([this.redis_database.getTCPest(ip, timewindow, TCPkey), this.redis_database.getUDPest(ip, timewindow, UDPkey)]).then(values=>{return values;})
    }

    /*Function to get the data from redis database for notestablished TCP and UDP connections*/
    set_tcp_udp_data_notest(ip, timewindow, TCPkey, UDPkey){
        return Promise.all([this.redis_database.getTCPnotest(ip, timewindow, TCPkey), this.redis_database.getUDPnotest(ip, timewindow, UDPkey)]).then(values=>{return values;})
    }

    /*Function to combine TCP and UDP data in one list separately for listtable and gauge widgets*/
    combine_tcp_udp(tcp_data, udp_data){
        return new Promise((resolve, reject)=>{
          let tcp_data_listtable = tcp_data[0]
          let tcp_data_gauge = tcp_data[1]
          let udp_data_listtable = udp_data[0]
          let udp_data_gauge = udp_data[1]
          let final_listtable = tcp_data_listtable.concat(udp_data_listtable)
          let final_gauge = tcp_data_gauge.concat(udp_data_gauge)
          resolve([final_listtable, final_gauge])
        })
    }

    /*Function to format TCP and UDP data for lsttable and gauges*/
    operate(ip, timewindow, TCP_key_established,  UDP_key_established, TCP_key_notestablished, UDP_key_notEstablished,listtable1_column_names,listtable2_column_names){
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

    /*Function to format TCP and UDP data for lsttable and gauges when it has IP as a column value*/
    operate_IPs(ip, timewindow, TCP_key_established,  UDP_key_established, TCP_key_notestablished, UDP_key_notEstablished, listtable1_column_names, listtable2_column_names){

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
                                            this.fake_control(val[0],val[1],listtable1_column_names,listtable2_column_names)
                                            }
                                        )
                                  }
                           )
                      }
      )
    }

    /*Function to  fake scroll listtable and gauge down simultaneously*/
    down(){
    if(this.gauge1.widget.focused == true){
        if(this.gauge1_counter >= (this.total_data1-1)*this.gauge_number);
        else{
          this.listtable1_counter += this.gauge_number*2
          this.gauge1_counter += this.gauge_number
          let listtable1_data_sliced = [this.listtable1_column_names,[],...this.listtable1_data.slice(this.listtable1_counter, this.listtable1_counter + this.gauge_number*2)]
          let gauge1_data_sliced = this.gauge1_data.slice(this.gauge1_counter, this.gauge1_counter + this.gauge_number)
          this.listtable1.setData([['']])
          this.listtable1.setData(listtable1_data_sliced)
          this.gauge1.setData(gauge1_data_sliced)
          this.screen.render()
        }
    }
    else{
        if(this.gauge2_counter >= (this.total_data2-1)*this.gauge_number);
        else{
          this.listtable2_counter += this.gauge_number*2
          this.gauge2_counter += this.gauge_number
          let listtable2_data_sliced = [this.listtable2_column_names,[],...this.listtable2_data.slice(this.listtable2_counter, this.listtable2_counter + this.gauge_number*2)]
          let gauge2_data_sliced = this.gauge2_data.slice(this.gauge2_counter, this.gauge2_counter + this.gauge_number)
          this.listtable2.setData(listtable2_data_sliced)
          this.gauge2.setData(gauge2_data_sliced)
          this.screen.render()
        }
    }
    return;
    }

    /*Function to fake scroll listtable and gauge up simultaneously*/
    up(){
        if(this.gauge1.widget.focused==true){
            this.listtable1_counter -= this.gauge_number*2
            this.gauge1_counter -= this.gauge_number
            if(this.listtable1_counter <= 0){this.listtable1_counter = 0; this.gauge1_counter = 0;}
            let listtable1_data_sliced = [this.listtable1_column_names,[],...this.listtable1_data.slice(this.listtable1_counter, this.listtable1_counter + this.gauge_number*2)]
            let gauge1_data_sliced = this.gauge1_data.slice(this.gauge1_counter, this.gauge1_counter + this.gauge_number)
            this.listtable1.setData(listtable1_data_sliced)
            this.gauge1.setData(gauge1_data_sliced)
            this.screen.render()
          }
        else{
            this.listtable2_counter -= this.gauge_number*2
            this.gauge2_counter -= this.gauge_number
            if(this.listtable2_counter <= 0){this.listtable2_counter = 0; this.gauge2_counter = 0;}
            let listtable2_data_sliced = [this.listtable2_column_names,[],...this.listtable2_data.slice(this.listtable2_counter, this.listtable2_counter + this.gauge_number*2)]
            let gauge2_data_sliced = this.gauge2_data.slice(this.gauge2_counter, this.gauge2_counter + this.gauge_number)
            this.listtable2.setData(listtable2_data_sliced)
            this.gauge2.setData(gauge2_data_sliced)
            this.screen.render()
        }
        return;
    }


    /*Initialize first page in widgets listtable and gauge*/
    fake_control(data_est, data_notest, listtable1_column_names, listtable2_column_names){
        this.listtable1_data = data_est[0]
        this.gauge1_data = data_est[1]

        this.listtable2_data = data_notest[0]
        this.gauge2_data = data_notest[1]

        this.listtable1_column_names = listtable1_column_names
        this.listtable2_column_names = listtable2_column_names
        this.listtable1_counter = 0
        this.listtable2_counter = 0
        this.gauge1_counter = 0
        this.gauge2_counter = 0
        this.gauge_number = 9
        this.total_data1 = Math.ceil(this.gauge1_data.length / this.gauge_number);
        this.total_data2 = Math.ceil(this.gauge2_data.length / this.gauge_number);
        let gauge1_data_sliced = this.gauge1_data.slice(0,this.gauge_number)
        this.gauge1.setData(gauge1_data_sliced)
        let gauge2_data_sliced = this.gauge2_data.slice(0,this.gauge_number)
        this.gauge2.setData(gauge2_data_sliced)
        let listtable1_data_sliced = [this.listtable1_column_names,[],...this.listtable1_data.slice(0,this.gauge_number*2)]
        this.listtable1.setData(listtable1_data_sliced)
        let listtable2_data_sliced =  [this.listtable2_column_names,[],...this.listtable2_data.slice(0,this.gauge_number*2)]
        this.listtable2.setData(listtable2_data_sliced)

        this.listtable1.show()
        this.listtable2.show()
        this.gauge1.show()
        this.gauge2.show()
        this.gauge1.focus()

        this.screen.render()
        return;
    }

}

module.exports = {combineClass: combine_Listtable_Gauge}
