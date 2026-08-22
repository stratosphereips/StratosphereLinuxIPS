// SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
//SPDX-License-Identifier: GPL-2.0-only
class Redis{
    constructor(redis, redis_port){
        this.redis = redis
        this.tree_redisClient = undefined
        this.BlockedIPsTWs = undefined
        this.redis_port = redis_port
    }


    getAllProfiles(){
        return new Promise((resolve, reject)=>{this.db.smembers("profiles",(err, reply) =>{
            if(err){console.log("Error in getAllProfiles() in database.js to retrieve all profiles from the database. Error: ", err); reject(err);}
            else{resolve(reply);}
            })
        })
    }

    getProfileTWs(key){
        return new Promise((resolve, reject) => {this.db.zrange(key,  0, -1, (err, reply)=>{
            if(err){console.log("Error in getProfileTWs in database.js to retrieve tws of the profile. Error: ",err); reject(err);}
            else{
            let d = {}
            d[key] = reply;
            resolve(reply);}
            })
        })
    }

    /*Get all the keys from the database.*/
  	getAllKeys(){
  		return new Promise((resolve,reject)=>{this.db.keys('*',(err, reply)=>{
  			if(err){console.log('Error in getAllKeys() in kalipso_redis.js to retrieve all keys from the database. Error: ',err); reject(err)}
  			else{resolve(reply)}
        });})
  	}

    /*Get blocked IPs and timewindows.*/
  	getBlockedIPsTWs(){
  		return new Promise((resolve,reject)=>{this.db.hgetall("BlockedProfTW",(err,reply)=>{
  			if(err){console.log("Error in the retrieving blocked IPs and timewindows. Error: ",err);reject(err)}
  			else{resolve(reply)}
  		});})
  	}

    /*Get host IP*/
    getHostIP(){
	    return new Promise((resolve,reject)=>{this.db.smembers('hostIP',(err,value)=>{
	      if(err){ console.log(err); reject(err);}
	      else{resolve(value) ;}
	  	});})
    }

    /*Get hostname of IP*/
    getHostnameOfIP(profileid){
	    return new Promise((resolve,reject)=>{this.db.hmget(profileid, 'host_name',(err,value)=>{
	      if(err){ console.log(err); reject(err);}
	      else{
              resolve(value[0]) ;}
	  	});})
    }

    /*Get timeline data for specific profile and timewindow*/
    getTimeline(ip, timewindow){
      return new Promise((resolve, reject)=>{ this.db.zrange("profile_"+ip+"_"+timewindow+'_timeline',0,-1, (err,reply)=>{
          if(err){console.log('Error in getTimeline in kalipso_redis.js. Error: ',err); reject(err);}
          else{resolve(reply);}
      });})
    }

    /*Get evidence for specific profile and timewindow*/
    getEvidence(ip, timewindow){
      return new Promise ((resolve, reject)=>{this.db.hget("profile_"+ip+"_"+timewindow,'Evidence',(err,reply)=>{
        if(err){console.log("Error in getEvidence() in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get DND resolution for specific IP*/
    getDNSResolution(ip){
      return new Promise((resolve,reject)=>{
        var resolved_dns = '';
        this.db.hget('DNSresolution',ip,(err,value)=> {
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
      return new Promise((resolve, reject)=>{this.cache.hget("IPsInfo",ip,(err,reply)=>{
        if(err){console.log("Error in getIpInfo in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get outtuples for specific profile and timewindow.*/
    getOutTuples(ip,timewindow){
      return new Promise ((resolve, reject)=>{this.db.hget("profile_"+ip+"_"+timewindow,'OutTuples',(err,reply)=>{
        if(err){console.log("Error in getOutTuples in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get intuples for specific profile and timewindow*/
    getInTuples(ip,timewindow){
      return new Promise ((resolve, reject)=>{this.db.hget("profile_"+ip+"_"+timewindow,'InTuples',(err,reply)=>{
        if(err){console.log("Error in getInTuples in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for UDP established connections (dst/src ports/ips client/server) for specific profile and timewindow*/
    getUDPest(ip, timewindow,udp_key){
      return new Promise ((resolve, reject)=>{this.db.hget("profile_"+ip+"_"+timewindow, udp_key,(err,reply)=>{
        if(err){console.log("Error in getUDPest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for TCP established (dst/src ports/IPs client/server) for specific profile and timewindow.*/
    getTCPest(ip, timewindow,tcp_key){
      return new Promise ((resolve, reject)=>{this.db.hget("profile_"+ip+"_"+timewindow,tcp_key,(err,reply)=>{
        if(err){console.log("Error in getTCPest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for UDP notestablished (dst/src ports/IPs client/server) for specific profile and timewindow*/
    getUDPnotest(ip, timewindow,udp_key){
      return new Promise ((resolve, reject)=>{this.db.hget("profile_"+ip+"_"+timewindow, udp_key,(err,reply)=>{
        if(err){console.log("Error in getUDPnotest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get data for TCP notestablished (dst/src port/ips client/server) for specific profile and timewindow*/
    getTCPnotest(ip, timewindow,tcp_key){
      return new Promise ((resolve, reject)=>{this.db.hget("profile_"+ip+"_"+timewindow,tcp_key,(err,reply)=>{
        if(err){console.log("Error in getTCPnotest in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Get all evidence for specific profile.*/
    getAllProfileEvidences(ip){
        return new Promise(
               (resolve,reject)=>{this.db.hgetall("evidenceprofile_"+ip, (err,reply)=>{
                   if(err){console.log("Error in getAllProfileEvidences in kalipso_redis.js. Error: ",err); reject(err);}
                   else{resolve(reply);}
               })}
        )
    }

    /*Get all slips processes PIDs.*/
    getPIDs(){
        return new Promise(
               (resolve,reject)=>{this.db.hgetall("PIDs", (err,reply)=>{
                   if(err){console.log("Error in getPIDs in kalipso_redis.js. Error: ",err); reject(err);}
                   else{resolve(reply);}
               })}
        )
    }

    /*Get starttime for the timewindow in the profile*/
    getStarttimeForTW(ip, timewindow){
      return new Promise ((resolve, reject)=>{this.db.zscore("twsprofile_"+ip,timewindow,(err,reply)=>{
        if(err){console.log("Error in getStarttimeForTW in kalipso_redis.js. Error: ",err); reject(err);}
        else{resolve(reply);}
      });})
    }

    /*Create all the client to the Redis database.*/
    createClient(){
        let redis_config = {
            host: "127.0.0.1",
            port: this.redis_port
            };

        let redis_cache_config = {
            host: "127.0.0.1",
            port: 6379        }
        this.db = this.redis.createClient(redis_config)
        this.cache = this.redis.createClient(redis_cache_config)
        this.cache.select(1)
  	}
}

module.exports = Redis
