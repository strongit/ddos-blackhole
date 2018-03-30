// author: InMon
// version: 1.0
// date: 10/10/2015
// description: Blackhole DDoS flood attacks

include(scriptdir()+'/inc/trend.js');

var trend = new Trend(300,1);
// var effectiveSamplingRateFlag = getSystemProperty("ddos_blackhole.esr") === "yes";
var points;

var other = '-other-';
function calculateTopN(metric,n,minVal,total_bps) {     
  var total, top, topN, i, bps;
  top = activeFlows('ALL',metric,n,minVal,'max'); // get top active flows
  var topN = {};
  if(top) {
    total = 0;
    for(i in top) {
      bps = top[i].value;
      topN[top[i].key] = bps;
      total += bps;
    }
    if(total_bps > total) topN[other] = total_bps - total;
  }
  return topN;
}

function totalTopN(metric,n,minVal,total_bps) {     
  var total, top, topN, i, bps, threshold;
  top = activeFlows('ALL',metric,n,minVal,'max'); // get top active flows
  var topN = {};
  if(top) {
    total = 0;
    for(i in top) {
      bps = top[i].value;
      topN[top[i].key] = bps;
      total += bps;
    }
  }
  sharedSet('ddos_blackhole_connections',total);
  return total;
}

var controls = {};

setIntervalHandler(function() {
  points = {};
  var counts = sharedGet('ddos_blackhole_controls_counts') || {};
  points['controls'] = counts.n || 0;
  points['controls_pending'] = counts.pending || 0;
  points['controls_failed'] = counts.failed || 0;
  points['controls_blocked'] = counts.blocked || 0;
  points['connections'] = sharedGet('ddos_blackhole_connections') || 0;
  points['routes'] = sharedGet('ddos_blackhole_routes') || 0;
  points['top-5-targets'] = calculateTopN('ddos_blackhole_target',5,1,0);
  points['top-5-protocols'] = calculateTopN('ddos_blackhole_protocol',5,1,0);
  points['total_topn'] = totalTopN('ddos_blackhole_target',20,1,0);
  trend.addPoints(points);
}, 1);

setHttpHandler(function(req) {
  var result, key, name, threshold, id, path = req.path;
  if(!path || path.length == 0) throw "not_found";
  switch(path[0]) {
    case 'trend':
      if(path.length > 1) throw "not_found"; 
      result = {};
      result.trend = req.query.after ? trend.after(parseInt(req.query.after)) : trend;
      result.trend.values = {};
      threshold = sharedGet('ddos_blackhole_pps');
      if(threshold) result.trend.values.threshold = threshold;
      id = sharedGet('ddos_blackhole_controls_id') || 0;
      result.trend.values.control_id = id;
      break;
    default: throw 'not_found';
  }
  return result;
});
