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
      this.ipInfo_data = this.redis.createClient()
  	}

  	getAllKeys(){
  		return new Promise((resolve,reject)=>{this.tree_keys.keys('*',(err, reply)=>{
  			if(err){console.log(err); reject(err)}
  			else{resolve(reply)}
  		});})
  	}

  	getBlockedIPsTWs(){
  		return new Promise((resolve,reject)=>{this.BlockedIPsTWs.smembers("BlockedProfTW",(err,reply)=>{
  			if(err){ console.log(err);reject(err)}
  			else{resolve(reply)}
  		});})
  	}

    getHostIP(){
	    return new Promise((resolve,reject)=>{this.client.get('hostIP',(err,value)=>{
	      if(err){ console.log(err); reject(err);}
	      else{resolve(value) ;}
	  	});})
    }

    getTimeline(ip, timewindow){
      return new Promise((resolve, reject)=>{ this.timeline_data.lrange("profile_"+ip+"_"+timewindow+'_timeline',0,-1, (err,reply)=>{
          if(err){console.log(err); reject(err);}
          else{resolve(reply);}
      });})
    }

    getEvidence(ip, timewindow){
      return new Promise ((resolve, reject)=>{this.evidence_data.hget("profile_"+ip+"_"+timewindow,'Evidence',(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
      });})
    }

    getIpInfo(ip){
      return new Promise((resolve, reject)=>{this.ipInfo_data.hget("IPsInfo",ip,(err,reply)=>{
        if(err){console.log(err); reject(err);}
        else{resolve(reply);}
    });})
    }
}
  module.exports = Redis