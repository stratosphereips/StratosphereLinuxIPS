  class Redis{
  	constructor(redis){
  		this.redis = redis
  		this.tree_redisClient = undefined
  		this.client = undefined
  		this.BlockedIPsTWs = undefined
  	}

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
        this.all_profile_tws = this.redis.createClient()
  	}

  	getAllKeys(){
      /*
      Get all the keys in redis
      */
  		return new Promise((resolve,reject)=>{this.tree_keys.keys('*',(err, reply)=>{
  			if(err){console.log(err); reject(err)}
  			else{resolve(reply)}
        });})
  	}

  	getBlockedIPsTWs(){
      /*
      Get all the blocked profiles and timewindows
      */
  		return new Promise((resolve,reject)=>{this.BlockedIPsTWs.smembers("BlockedProfTW",(err,reply)=>{
  			if(err){ console.log(err);reject(err)}
  			else{resolve(reply)}
  		});})
  	}

    getHostIP(){
      /*
      Get an IP of host machine
      */
	    return new Promise((resolve,reject)=>{this.client.smembers('hostIP',(err,value)=>{
	      if(err){ console.log(err); reject(err);}
	      else{resolve(value) ;}
	  	});})
    }

    getTimeline(ip, timewindow){
      /*
      Get timeline data for specific profile and timewindow
      */
      return new Promise((resolve, reject)=>{ this.timeline_data.zrange("profile_"+ip+"_"+timewindow+'_timeline',0,-1, (err,reply)=>{
          if(err){console.log(err); reject(err);}
          else{resolve(reply);}
      });})
    }

    getEvidence(ip, timewindow){
      /*
      Get evidence for specific profile and timewindow
      */
      return new Promise ((resolve, reject)=>{this.evidence_data.hget("profile_"+ip+"_"+timewindow,'Evidence',(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
      });})
    }

    getDNSResolution(ip){
      /*
      Get DNS resolution of the IP
      */
      return new Promise((resolve,reject)=>{
        var resolved_dns = '';
        this.redis_resolved_dns.hget('DNSresolution',ip,(err,value)=> {
          if(err){reject(resolved_dns)}
          else{
            if(value == null){
              value = ''
            }
            resolved_dns = value
            resolve(resolved_dns)
          }
        })
      })
    }
    
    getIpInfo(ip){
      /*
      Get IP information - asn, geocountry, VT - for specific IP
      */
      return new Promise((resolve, reject)=>{this.ipInfo_data.hget("IPsInfo",ip,(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
      });})
    }
    getOutTuples(ip,timewindow){
      /*
      Get OutTuples - IP/Port/protocol + behavioral letters- for specific profile and timewindow
      */
      return new Promise ((resolve, reject)=>{this.outTuples_data.hget("profile_"+ip+"_"+timewindow,'OutTuples',(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
      });})
    }
    getInTuples(ip,timewindow){
      /*
      Get InTuples - IP/Port/protocol + behavioral letters- for specific profile and timewindow
      */
      return new Promise ((resolve, reject)=>{this.inTuples_data.hget("profile_"+ip+"_"+timewindow,'InTuples',(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
      });})
    }
    
    getUDPest(ip, timewindow,udp_key){
      /*
      Get appropriate data for UDP established (dst/src Ports/IPs, slient/server) for specific profile and timewindow
      */
      return new Promise ((resolve, reject)=>{this.udp_data_est.hget("profile_"+ip+"_"+timewindow, udp_key,(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
      });})
    }
    getTCPest(ip, timewindow,tcp_key){
      /*
      Get appropriate data for TCP established (dst/src Ports/IPs, slient/server) for specific profile and timewindow
      */
      return new Promise ((resolve, reject)=>{this.tcp_data_est.hget("profile_"+ip+"_"+timewindow,tcp_key,(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
      });})
    }
    getUDPnotest(ip, timewindow,udp_key){
      /*
      Get appropriate data for UDP notestablished (dst/src Ports/IPs, slient/server) for specific profile and timewindow
      */
      return new Promise ((resolve, reject)=>{this.udp_data_notest.hget("profile_"+ip+"_"+timewindow, udp_key,(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{
          resolve(reply);}
      });})
    }
    getTCPnotest(ip, timewindow,tcp_key){
      /*
      Get appropriate data for TCP notestablished (dst/src Ports/IPs, slient/server) for specific profile and timewindow
      */
      return new Promise ((resolve, reject)=>{this.tcp_data_notest.hget("profile_"+ip+"_"+timewindow,tcp_key,(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{

          resolve(reply);}
      });})
    }

    getAllProfileEvidence(ip){
    /*
    Get all evidence in the profile.
    */
        return new Promise(
               (resolve,reject)=>{this.all_profile_evidences.hgetall("evidenceprofile_"+ip, 0, -1, (err,reply)=>{
                   if(err){console.log(err); reject(err);}
                   else{
                        resolve(reply);
                   }
               })}
        )
    }
}
  module.exports = Redis