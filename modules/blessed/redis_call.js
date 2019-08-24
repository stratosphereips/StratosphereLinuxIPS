var redis = require('redis')

var redis_tree = redis.createClient()


var ips_with_profiles = [];


redis_tree.keys('*', (err,reply)=>{
	parallel(reply)
	// console.log(reply)

// 	let chain = Promise.resolve();

// for (var i of reply) {
//    chain = chain.then(c(i))
// }

// chain.then(()=>{console.log(ips_with_profiles)})
					})


	
function c(i){
	if(i.includes('timewindow')){ips_with_profiles.push(i.split('_')[1]);}
}

function parallel(reply) {
  return Promise.all(reply.map( ke => c(ke))).then(console.log(ips_with_profiles));//handle result)
  }


// // let promise = redis_tree.keys('*')
// // let promise2 = promise.then(function(err){},function(reply){})
// function get_IPs_with_profiles(callback){
// 		/*
// 		retrieve ips with profile from redis key 'Profiles'
// 		*/
// 		var ips_with_profiles = [];
// 		redis_tree.keys('*', (err,reply)=>{
// 			if(err){callback(err)}
// 			async.each(reply, function(key,callback){
// 				if(key.includes('timewindow')){
// 					ips_with_profiles.push(key.split('_')[1]);
// 				}
// 				callback(null)
// 			},function(err) {

// 		 if( err ) {
// 		 	console.log('unable to create user');
// 		 }else {
// 		 	callback(null, ips_with_profiles);
// 		 };
// 		})










// async.waterfall([
// 	/*async_waterfall to fill the data for the tree*/
// 	function get_IPs_with_profiles(callback){
// 		/*
// 		retrieve ips with profile from redis key 'Profiles'
// 		*/
// 		var ips_with_profiles = [];
// 		redis_tree.keys('*', (err,reply)=>{
// 			if(err){callback(err)}
// 			async.each(reply, function(key,callback){
// 				if(key.includes('timewindow')){
// 					ips_with_profiles.push(key.split('_')[1]);
// 				}
// 				callback(null)
// 			},function(err) {

// 		 if( err ) {
// 		 	console.log('unable to create user');
// 		 }else {
// 		 	callback(null, ips_with_profiles);
// 		 };
// 		})


// })},

// 	function get_tws_for_ips(ips_with_profiles, callback){
// 		var tree_dict = {};
// 		function createUser(ip_profile, reply, callback)
// 		{
// 			tree_dict[ip_profile]=timewindows_list_per_ip(reply);	
// 		 	callback(null);
// 		}
// 		async.each(ips_with_profiles, function(ip_profile, callback) {
// 		redis_tws_for_ip.zrangebyscore("twsprofile_"+ip_profile,
// 		   			Number.NEGATIVE_INFINITY,Number.POSITIVE_INFINITY, (err,reply)=>{
// 		    			if(err){
// 		      				callback(err);
// 		   				}else{
// 		   					createUser(ip_profile,reply, callback);
// 		        	}})
// 		}, function(err,res) {
// 		 if( err ) {
// 		 console.log('unable to create user');
// 		 } else {		 
// 		 callback(null,  tree_dict);

// 		 }
// 		})}, 

//   	function setTree(timewindows_list,callback){
//   		tree.setData(set_tree_data(timewindows_list));
//   		screen.render();
//   		callback(null)
//   	}
// ], function(err){if(err){console.log(err)}});