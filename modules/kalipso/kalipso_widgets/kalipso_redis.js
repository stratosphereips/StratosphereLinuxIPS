class Redis{
    constructor(redis){
        this.redis = redis
        this.tree_redisClient = undefined
        this.client = undefined
        this.BlockedIPsTWs = undefined
    }

    /*Create all the client to the Redis database.*/
    createClient(){
        this.tree_keys = this.redis.createClient()
  		this.BlockedIPsTWs = this.redis.createClient()
        this.client = this.redis.createClient()
        this.timeline_data = this.redis.createClient()
        this.evidence_data = this.redis.createClient()
        this.ipInfo_data = this.redis.createClient({'db':1})
        this.outTuples_data = this.redis.createClient()
        this.inTuples_data = this.redis.createClient()
        this.tcp_data_est = this.redis.createClient()
        this.udp_data_est = this.redis.createClient()
        this.tcp_data_notest = this.redis.createClient()
        this.udp_data_notest = this.redis.createClient()
        this.redis_resolved_dns = this.redis.createClient()
        this.all_profile_evidences = this.redis.createClient()
        this.tw_starttime = this.redis.createClient()
  	}

    /*Get all the keys from the database.*/
  	getAllKeys(){
  		return new Promise((resolve,reject)=>{this.tree_keys.keys('*',(err, reply)=>{
  			if(err){console.log('Error in getAllKeys() in kalipso_redis.js to retrieve all keys from the database. Error: ',err); reject(err)}
  			else{resolve(reply)}
        });})
  	}

    /*Get blocked IPs and timewindows.*/
  	getBlockedIPsTWs(){
  		return new Promise((resolve,reject)=>{this.BlockedIPsTWs.smembers("BlockedProfTW",(err,reply)=>{
  			if(err){console.log("Error in the retrieving blocked IPs and timewindows. Error: ",err);reject(err)}
  			else{resolve(reply)}
  		});})
  	}

    /*Get host IP*/
    getHostIP(){
	    return new Promise((resolve,reject)=>{this.client.smembers('hostIP',(err,value)=>{
	      if(err){ console.log(err); reject(err);}
	      else{resolve(value) ;}
	  	});})
    }

    /*Get hostname of IP*/
    getHostnameOfIP(profileid){
	    return new Promise((resolve,reject)=>{this.client.hmget(profileid, 'host_name',(err,value)=>{
	      if(err){ console.log(err); reject(err);}
	      else{
              resolve(value[0]) ;}
	  	});})
    }

    /*Get timeline data for specific profile and timewindow*/
    getTimeline(ip, timewindow){
      return new Promise((resolve, reject)=>{ this.timeline_data.zrange("profile_"+ip+"_"+timewindow+'_timeline',0,-1, (err,reply)=>{
          if(err){console.log('Error in getTimeline in kalipso_redis.js. Error: ',err); reject(err);}
          else{resolve(reply);}
      });})
    }

    /*Get evidence for specific profile and timewindow*/
    getEvidence(ip, timewindow){
      return new Promise ((resolve, reject)=>{this.evidence_data.hget("profile_"+ip+"_"+timewindow,'Evidence',(err,reply)=>{
        if(err){console.log("Error in getEvidence() in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get DND resolution for specific IP*/
    getDNSResolution(ip){
      return new Promise((resolve,reject)=>{
        var resolved_dns = '';
        this.redis_resolved_dns.hget('DNSresolution',ip,(err,value)=> {
          if(err){console.log('Error in getDNSResolution() in kalipso_redis.js. Error: ',err);
                  reject(resolved_dns)}
          else{
            if(value == null){value = ''}
            resolved_dns = value
            resolve(resolved_dns)
          }
        })
      })
    }

    /*Get information about the specific IP*/
    getIpInfo(ip){
      return new Promise((resolve, reject)=>{this.ipInfo_data.hget("IPsInfo",ip,(err,reply)=>{
        if(err){console.log("Error in getIpInfo in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get outtuples for specific profile and timewindow.*/
    getOutTuples(ip,timewindow){
      return new Promise ((resolve, reject)=>{this.outTuples_data.hget("profile_"+ip+"_"+timewindow,'OutTuples',(err,reply)=>{
        if(err){console.log("Error in getOutTuples in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get intuples for specific profile and timewindow*/
    getInTuples(ip,timewindow){
      return new Promise ((resolve, reject)=>{this.inTuples_data.hget("profile_"+ip+"_"+timewindow,'InTuples',(err,reply)=>{
        if(err){console.log("Error in getInTuples in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for UDP established connections (dst/src ports/ips client/server) for specific profile and timewindow*/
    getUDPest(ip, timewindow,udp_key){
      return new Promise ((resolve, reject)=>{this.udp_data_est.hget("profile_"+ip+"_"+timewindow, udp_key,(err,reply)=>{
        if(err){console.log("Error in getUDPest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for TCP established (dst/src ports/IPs client/server) for specific profile and timewindow.*/
    getTCPest(ip, timewindow,tcp_key){
      return new Promise ((resolve, reject)=>{this.tcp_data_est.hget("profile_"+ip+"_"+timewindow,tcp_key,(err,reply)=>{
        if(err){console.log("Error in getTCPest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for UDP notestablished (dst/src ports/IPs client/server) for specific profile and timewindow*/
    getUDPnotest(ip, timewindow,udp_key){
      return new Promise ((resolve, reject)=>{this.udp_data_notest.hget("profile_"+ip+"_"+timewindow, udp_key,(err,reply)=>{
        if(err){console.log("Error in getUDPnotest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for TCP notestablished (dst/src port/ips client/server) for specific profile and timewindow*/
    getTCPnotest(ip, timewindow,tcp_key){
      return new Promise ((resolve, reject)=>{this.tcp_data_notest.hget("profile_"+ip+"_"+timewindow,tcp_key,(err,reply)=>{
        if(err){console.log("Error in getTCPnotest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get all evidence for specific profile.*/
    getAllProfileEvidences(ip){
        return new Promise(
               (resolve,reject)=>{this.all_profile_evidences.hgetall("evidenceprofile_"+ip, (err,reply)=>{
                   if(err){console.log("Error in getAllProfileEvidences in kalipso_redis.js. Error: ",err); reject(err);}
                   else{resolve(reply);}
               })}
        )
    }

    /*Get starttime for the timewindow in the profile*/
    getStarttimeForTW(ip, timewindow){
      return new Promise ((resolve, reject)=>{this.tw_starttime.zscore("twsprofile_"+ip,timewindow,(err,reply)=>{
        if(err){console.log("Error in getStarttimeForTW in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }
}

module.exports = Redis