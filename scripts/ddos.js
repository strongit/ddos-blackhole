// author: InMon
// version: 2.0
// date: 6/15/2017
// description: Blackhole DDoS flood attacks
// copyright: Copyright (c) 2015-2017 InMon Corp.

include(scriptdir()+'/inc/trend.js');

var trend = new Trend(300,1);

var points;

var router_ip = getSystemProperty("ddos_blackhole.router")   || '127.0.0.1';
var my_as     = getSystemProperty("ddos_blackhole.as")       || '65000';
var my_id     = getSystemProperty("ddos_blackhole.id")       || '0.6.6.6';
var community = getSystemProperty("ddos_blackhole.community")|| '65535:666';
var nexthop   = getSystemProperty("ddos_blackhole.nexthop")  || '192.0.2.1';
var localpref = getSystemProperty("ddos_blackhole.localpref")|| '100';

var effectiveSamplingRateFlag = getSystemProperty("ddos_blackhole.esr") === "yes";
var flow_t = getSystemProperty("ddos_blackhole.flow_seconds")|| '2';

var externalGroup= getSystemProperty("ddos_blackhole.externalgroup")   || 'external';
var excludedGroups= getSystemProperty("ddos_blackhole.excludedgroups") || 'external,private,multicast,exclude';

var defaultGroups = {
  external:['0.0.0.0/0'],
  private:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'],
  multicast:['224.0.0.0/4'],
};

var filter = 'group:ipsource:ddos_blackhole='+externalGroup;
filter += '&group:ipdestination:ddos_blackhole!='+excludedGroups;

var groups = storeGet('groups')               || defaultGroups; //	逻辑运算符&& ||, storeGet(key):Get value from persistent store
var threshold = storeGet('threshold')         || 100000000;
var block_minutes = storeGet('block_minutes') || 60;

var controls = {};

// 统计牵引状态节点数
function updateControlCounts() {
  var counts = { n: 0, blocked: 0, pending: 0, failed: 0};
  for(var addr in controls) {
    counts.n++;
    switch(controls[addr].status) {
    case 'blocked':
      counts.blocked++;
      break;
    case 'pending':
      counts.pending++;
      break;
    case 'failed':
      counts.failed++;
      break;
    } 
  }
  sharedSet('ddos_blackhole_controls_counts',counts);
}

var enabled = storeGet('enabled') || false;

var bgpUp = false;

function blockRoute(address) {
  return {prefix:address, nexthop:nexthop, communities:community, localpref:localpref};
}

function bgpOpen() {
  bgpUp = true;
  sharedSet('ddos_blackhole_connections',1);

  // re-install controls
  for(var addr in controls) {
    var rec = controls[addr];
    if(rec.status === 'blocked' || rec.status === 'failed') {
      if(bgpAddRoute(router_ip, blockRoute(addr))) {
        rec.status = 'blocked';
      }
      else {
        logWarning("DDoS block failed, " + addr);
        rec.status = 'failed';
      } 
    }
  }
  updateControlCounts();
}

function bgpClose() {
  bgpUp = false;
  sharedSet('ddos_blackhole_connections',0);

  // update control status
  for(var addr in controls) {
    var rec = controls[addr];
    if(rec.status === 'blocked') rec.status = 'failed';
  }
  updateControlCounts();
}

bgpAddNeighbor(router_ip, my_as, my_id, null, bgpOpen, bgpClose);

setGroups('ddos_blackhole', groups);

setFlow('ddos_blackhole_target', 
  { keys:'ipdestination,group:ipdestination:ddos_blackhole', value:'bytes', filter:filter, t:flow_t }
);

setFlow('ddos_blackhole_protocol',
  { keys:'ipdestination,stack', value:'bytes', filter:filter, t:flow_t }
);

// 设置DDoS阈值
function setDDoSThreshold(bps) {
  setThreshold('ddos_blackhole_attack',
    {metric:'ddos_blackhole_target',value:threshold,byFlow:true,timeout:10}
  );
  sharedSet('ddos_blackhole_pps',bps);  // 保存阈值到存储区
}

setDDoSThreshold(threshold);


function in_array(arr, obj) {  
    var i = arr.length;  
    while (i--) {  
        if (arr[i] === obj) {  
            return true;  
        }  
    }  
    return false;  
} 

function block(address,info,operator) {
  if(!controls[address]) {
    logInfo("DDoS blocking " + address);
	// 当发生牵引时，进行告警
    // http('http://127.0.0.1:5000/mail/' + address + '/block');
    // let rec = { action: 'block', time: (new Date()).getTime(), status:'pending', info:info };
    let rec = { action: 'block', time: (new Date()).getTime(), status:'pending', info:info , times: 0 };
    controls[address] = rec;
    if(enabled || operator) {
      if(bgpAddRoute(router_ip, blockRoute(address))) {
        rec.status = 'blocked';
        rec.times++;
      }
      else {
        logWarning("DDoS block failed, " + address);
        rec.status = 'failed';
      }
	}
  } else if(operator) {
    // operator confirmation of existing control
    let rec = controls[address];
    if('pending' === rec.status) {
      if(bgpAddRoute(router_ip,blockRoute(address))) {
        rec.status = 'blocked';
      }
      else {
        logWarning("DDoS block failed, " + address);
        rec.status = 'failed';
      }
    }
  }
  updateControlCounts();
}

function allow(address,info,operator) {
  if(controls[address]) {
    logInfo("DDoS allowing " + address);
	// 当牵引结束时，进行告警
    // http('http://127.0.0.1:5000/mail/' + address + '/allow');
    let rec = controls[address];
    if('blocked' === rec.status) {
      if(bgpRemoveRoute(router_ip,address)) {
        delete controls[address];
      }
      else {
        logWarning("DDoS allow failed, " + address);
        rec.status = 'failed';
      }
    } else {
      delete controls[address];
    }
  }
  updateControlCounts();
}

// function totalTopN(metric,n,minVal,total_bps) {     
//   var total, top, topN, i, bps, threshold;
//   top = activeFlows('ALL',metric,n,minVal,'max'); // get top active flows
//   var topN = {};
//   if(top) {
//     total = 0;
//     for(i in top) {
//       bps = top[i].value;
//       topN[top[i].key] = bps;
//       total += bps;
//     }
//   }
//   logInfo("total rate01 is ", total);
//   return total;
// }

setEventHandler(function(evt) {
  var [ip,group] = evt.flowKey.split(',');
  if(controls[ip]) return;
  // don't allow data from data sources with sampling rates close to threshold
  // avoids false positives due the insufficient samples
  if(effectiveSamplingRateFlag) {
    let dsInfo = datasourceInfo(evt.agent,evt.dataSource);
    if(!dsInfo) return;
    let rate = dsInfo.effectiveSamplingRate;
    if(!rate || rate > (threshold / 10)) {
      // logWarning("DDoS effectiveSampling rate " + rate + " too high for " + evt.agent);
      logInfo("DDoS effectiveSampling rate " + rate + " too high for " + evt.agent);
      return;
    }
  }

  // gather supporting data
  var info = {group:group};
  var keys = metric(evt.agent,evt.dataSource+'.ddos_blackhole_protocol')[0].topKeys;
  if(keys) {
    let majorityThresh = evt.value / 2;
    let entry = keys.find(function(el) el.key.split(',')[0] === ip && el.value > majorityThresh);
    if(entry) {
       let [,stack] = entry.key.split(',');
       info['stack'] = stack;
    }
  }

  block(ip,info,false);
},['ddos_blackhole_attack']);

// block时检测是否可以allow
setIntervalHandler(function() {
  var now = (new Date()).getTime();
  var threshMs = block_minutes * 60000;
  var total;
  points = {};
  threshold = sharedGet('ddos_blackhole_pps');
  total = sharedGet('ddos_blackhole_connections');
  logInfo("total top_20 rate is ", total);
  for(var addr in controls) {
    logInfo("threshMs time is :",threshMs);
    if(now - controls[addr].time > threshMs) allow(addr,{},false);
    if(!total || total > ((threshold / 10) * 0.8)) {
      logInfo("DDoS total rate " + total);
      block(addr,{},false);
    }
  }
  // trend.addPoints(points);
}, 1);

setHttpHandler(function(req) {
  var result, key, name, path = req.path;
  if(!path || path.length == 0) throw "not_found";
  switch(path[0]) {
    case 'controls':
      result = {};
      var action = '' + req.query.action;
      switch(action) {
        case 'block':
          var address = req.query.address[0];
          if(address) {
            block(address,{},true);
          }
          break;
        case 'allow':
          var address = req.query.address[0];
          if(address) allow(address,{},true);
          break;
        case 'enable':
          enabled = true;
          storeSet('enabled',enabled)
          break;
        case 'disable':
          enabled = false;
          storeSet('enabled')
          break;
      }
      result.controls = [];
      for(addr in controls) {
        let ctl = controls[addr];
        let entry = {
          target: addr,
          group: ctl.info.group,
          protocol: ctl.info.stack ? ctl.info.stack : '',
          time: ctl.time,
          status: ctl.status 
        }
        result.controls.push(entry); 
      };
      result.enabled = enabled;
      break;
    case 'threshold':
      if(path.length > 1) throw "not_found";
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error) throw "bad_request"
          threshold = parseInt(req.body);
          setDDoSThreshold(threshold);
          storeSet('threshold',threshold);
          break;
        default:
          result = threshold;
      }
      break;
    case 'blockminutes':
      if(path.length > 1) throw "not_found";
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error) throw "bad_request"
          block_minutes = parseInt(req.body);
          storeSet('block_minutes',block_minutes);
          break;
        default:
          result = block_minutes;
      }
      break;
    case 'groups':
      if(path.length > 1) {
        if(path.length === 2 && 'info' === path[1]) {
          let ngroups = 0; ncidrs = 0;
          for (let grp in groups) {
            ngroups++;
            ncidrs += groups[grp].length;
          }
          result = {groups:ngroups, cidrs:ncidrs}; 
        }
        else throw "not_found";
      } else {
        switch(req.method) {
          case 'POST':
          case 'PUT':
            if(req.error) throw "bad_request";
            if(!setGroups('ddos_blackhole', req.body)) throw "bad_request";
            groups = req.body;
            storeSet('groups', groups);
            break;
          default: return groups;
        }
      }
      break;
    default: throw 'not_found';
  }
  return result;
});
