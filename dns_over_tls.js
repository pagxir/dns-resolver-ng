const tls = require('tls');
const fs = require('fs');
const net = require('net');
const http = require('http');
const dgram = require('dgram');
const table = require('./apnic-table-6');
const dnsp = require('dns-packet');
const assert = require('assert');
const querystring = require('querystring');

const options = {
  key: fs.readFileSync('certificate/tls.key'),
  cert: fs.readFileSync('certificate/fullchain.cer'),
  requestCert: false,
  ca: [ fs.readFileSync('certificate/ca.cer') ]
};

let dumpFirst = 0;
// if (table.lookup());

// const LOG_DEBUG = () => {};
const LOG_ERROR = console.log;
const LOG_DEBUG = console.log;

const additionals_with_subnet = {
  name: ".",
  type: "OPT",
  udpPayloadSize: 4096,
  extendedRcode: 0,
  ednsVersion: 0,
  flags: 0,
  flag_do: false,
  options: [
    {code: 8, type: "CLIENT_SUBNET", family: 1, sourcePrefixLength: 24, scopePrefixLength: 0, ip: "0.0.0.0"}
  ]
};

function dnsSetClientSubnet(msg, clientip) {

  let parts = clientip.split(".");
  let clientipstr = parts[0] + "." + parts[1] + "." + parts[2] + ".0";

  let additionals0 = Object.assign({}, additionals_with_subnet);

  additionals0.options[0].ip = clientipstr;

  if (msg.questions && !msg.questions.find(item => item.type == 'A')) {
    return msg;
  }

  if (msg.additionals) {
    let injected = false;

    let mapOptions = item => {
      if (!item.options) return item;

      if (item.name == '.' && item.type == "OPT") {
        item.options = item.options.filter(item => !item.type || item.type != "CLIENT_SUBNET");
        item.options.push(additionals0.options[0]);
        injected = true;
      }

      return item;
    };

    msg.additionals = msg.additionals.map(mapOptions);
    if (!injected) msg.additionals.push(additionals0);
  }

  return msg;
}

function dnsNomalize(data) {

  if (data.additionals) {

    var opt_map = item => {
      if (!item.options) return item;

      item.options = item.options.filter(item => !item.type || item.type != "PADDING");
      return item;
    };

    data.additionals = data.additionals.map(opt_map);
  }

  return data;
}

const FAR_PORT = 53;
const FAR_SERVER = "::ffff:8.8.8.8";

const NEAR_PORT = 53;
const NEAR_SERVER = "::ffff:223.5.5.5";
// const NEAR_SERVER = "::ffff:119.29.29.29";

const IPV4_NEAR_PREFERENE = 1;
const IPV4_FAR_PREFERENE  = 3;

const IPV6_NEAR_PREFERENE = 2;
const IPV6_FAR_PREFERENE  = 3;

const NAT64_NEAR_PREFERENE = 8;
const NAT64_FAR_PREFERENE  = 3;

const INVALIDE_PREFERENE   = 100;
const DETECT_DOMAIN_SUFFIEX = ".oil.cootail.com";

const DETECT_DOMAIN_JSON = {
  type: 'query',
  id: 26858,
  flags: dnsp.RECURSION_DESIRED,
  questions: [{
    type: 'A',
    name: 'google.com'
  }]
};

let DETECHCACHE = {};

function getDetectStatus(message) {
  const qname = message.questions[0].name;
  const key = qname.toLowerCase();

  if (qname.endsWith(DETECT_DOMAIN_SUFFIEX)) {
    return "Ok";
  }

  if (message.answers.length != 1) {
    return "Ok";
  }

  if (DETECHCACHE[key]) {
    return DETECHCACHE[key];
  }

  return "Chaos";
}

function doAutoRetry(callback) {
    callback();
    setTimeout(callback, 360);
    setTimeout(callback, 1360);
    return;
}

function dnsSendQuery(session, client, message) {
  let near_answered = false;
  let far_answered = false;
  let fake_answered = false, fake_request = false;

  client.timer = null;

  const onMessage = function(resolv) {
    return (segment, rinfo) => {
      let msg = dnsp.decode(segment);
      // LOG_DEBUG("response " + JSON.stringify(msg));
      // LOG_DEBUG("rinfo " + rinfo.address + " fast " + NEAR_SERVER + " slow " + FAR_SERVER);

      const qname = msg.questions[0].name;
      if (fake_request && qname.endsWith(DETECT_DOMAIN_SUFFIEX)) {

        const originName = qname.replace(DETECT_DOMAIN_SUFFIEX, "").toLowerCase();

        if (msg.answers.find(item => item.type == 'A' && item.data == "127.127.127.127")) {
          LOG_DEBUG("cachedOK " + originName);
          DETECHCACHE[originName] = "cachedOK";
        } else if (msg.answers.find(item => item.type == 'A' && item.data != "127.127.127.127")) {
          LOG_DEBUG("cachedBad " + originName);
          DETECHCACHE[originName] = "cachedBad";
        }

        fake_answered = true;
      } else if (rinfo.address == NEAR_SERVER && !near_answered) {
        near_answered = true;
        session.nearCaches[msg.questions[0].type] = msg;
        /*"Ok":"cachedOK":"cachedBad": */
        if (getDetectStatus(msg) == "Chaos") {
          LOG_DEBUG("detect start " + qname);
          const detectMessage = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
          detectMessage.questions[0].name = qname + DETECT_DOMAIN_SUFFIEX;
          fake_request = true;

          const oil_msg = dnsp.encode(detectMessage);
          let oil_out = v => fake_answered || client.send(oil_msg, FAR_PORT, FAR_SERVER, (err) => {  });

          doAutoRetry(oil_out);
          client.reset();
        }
      } else if (rinfo.address == FAR_SERVER && !far_answered) {
        session.farCaches[msg.questions[0].type] = msg;
        far_answered = true;
      }

      // LOG_DEBUG("slow_answer " + far_answered + " fast_answer " + near_answered);
      if (far_answered && near_answered && fake_request == fake_answered) {
        resolv(session);
      }
    }
  };

  let msg = dnsNomalize(message);
  const type = msg.questions[0].type;
  const qname = msg.questions[0].name;

  // dnsSetClientSubnet(msg, "103.70.115.29");
  const far_msg = dnsp.encode(msg);
  let far_out = v => far_answered || client.send(far_msg, FAR_PORT, FAR_SERVER, (err) => { LOG_DEBUG(` far send: ${qname} ${type} ${err}`); });

  dnsSetClientSubnet(msg, "117.144.103.197");
  const near_msg = dnsp.encode(msg);
  let near_out = v => near_answered || client.send(near_msg, NEAR_PORT, NEAR_SERVER, (err) => { LOG_DEBUG(`near send: ${qname} ${type} ${err}`); });

  doAutoRetry(near_out);
  doAutoRetry(far_out);

  const cb = (resolv, reject) => {
    client.on('error', reject);
    client.on('message', onMessage(resolv));
    client.reset = function () {
        if (this.timer) clearTimeout(this.timer);
        this.timer = setTimeout(reject, 3300);
    }
    client.reset();
  };

  return new Promise(cb);
}

function dnsDispatchQuery(session, message) {
  const client = dgram.createSocket('udp6');

  LOG_DEBUG("QUERY " + JSON.stringify(message.questions[0]));
  return dnsSendQuery(session, client, message).finally(v => client.close());
}

let OLD_SESSION = {};
let NEW_SESSION = {};

let SESSION = OLD_SESSION;
let old_new_stamp = new Date().getTime();

function isInjectHttps(domain)
{
   let lowerDomain = domain.toLowerCase();

   const categories = ["www.v2ex.com", "cdn.v2ex.com", "www.quora.com", "auth0.openai.com", "tcr9i.openai.com", "tcr9i.chat.openai.com", "cdn.oaistatic.com", "cdn.auth0.com", "cdn.openai.com", "api.openai.com", "platform.openai.com", "gist.github.com", "chat.openai.com", "jp.v2ex.com"]

   return lowerDomain.includes("v2ex.com") || categories.includes(lowerDomain);
}

function setFakeSession(session, key)
{
  const emptyResponse = (key, type) => {
    let fakeResponse = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
    fakeResponse.questions[0].name = key;
    fakeResponse.questions[0].type = type;
  };

  session.nearCaches['AAAA'] = emptyResponse(key, 'AAAA');
  session.farCaches['AAAA'] = emptyResponse(key, 'AAAA');
  session.nearCaches['A'] = emptyResponse(key, 'A');
  session.farCaches['A'] = emptyResponse(key, 'A');

  session.types['AAAA'] =  "DONE";
  session.types['A'] =  "DONE";
}
function getSession(key) {

  const stamp = new Date().getTime();

  if (old_new_stamp + 15000 < stamp) {
    if (SESSION === OLD_SESSION) {
      SESSION = NEW_SESSION = {};
      old_new_stamp = stamp;
    } else if (SESSION === NEW_SESSION) {
      SESSION = OLD_SESSION = {};
      old_new_stamp = stamp;
    }
  }

  if (OLD_SESSION[key]) {
    SESSION == OLD_SESSION || (SESSION[key] = OLD_SESSION[key]);
    return OLD_SESSION[key];
  }

  if (NEW_SESSION[key]) {
    SESSION == NEW_SESSION || (SESSION[key] = NEW_SESSION[key]);
    return NEW_SESSION[key];
  }

  let session = {nearCaches: {}, farCaches: {}, types: {}, key: key, allows: {}};
  SESSION[key] = session;
  if (key == "ipv4only.arpa") {
    setFakeSession(session, key);

    let fakeResponse = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
    fakeResponse.questions[0].name = key;
    session.nearCaches['A'] = fakeResponse;
    fakeResponse.questions[0].type = "AAAA";
    fakeResponse.answers = [{"name":key,"type":"AAAA","ttl":600,"class":"IN","flush":false,"data":"2002:1769:c6bd:ffff::"}];

    session.nearCaches['AAAA'] = fakeResponse;
    session.farCaches['AAAA'] = fakeResponse;
  }


  if (key == "mtalk.google.com") {
    let fake4Response = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
    fake4Response.questions[0].name = key;
    fake4Response.answers = [{"name":key,"type":"A","ttl":27,"class":"IN","flush":false,"data":"74.125.137.188"}];

    session.nearCaches['A'] = fake4Response;
    session.farCaches['A'] = fake4Response;

    let fake6Response = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
    fake6Response.questions[0].name = key;
    fake6Response.answers = [{"name":key,"type":"AAAA","ttl":27,"class":"IN","flush":false,"data":"2404:6800:4008:c06::bc"}];
    // fake6Response.answers = [{"name":key,"type":"AAAA","ttl":27,"class":"IN","flush":false,"data":"2404:6800:4008:c00::bc"}];

    session.nearCaches['AAAA'] = fake6Response;
    session.farCaches['AAAA'] = fake6Response;

    session.types['AAAA'] =  "DONE";
    session.types['A'] =  "DONE";
  }

  return session;
}

function dnsFetchQuery(fragment, preload = false) {

  const query = dnsp.decode(fragment);
  const domain = query.questions[0].name;
  const qtype  = query.questions[0].type;

  const session = getSession(domain.toLowerCase());

  if (!Object.values(session.types).includes("PENDING")) {
    session.promise = new Promise((resolv, reject) => {
      session.resolv = resolv;
      session.reject = reject;
    });
  }

  if (qtype in session.types)
    LOG_DEBUG("types " + qtype + " = " + session.types[qtype] + " key " + domain)
  else
    session.types[qtype] = "PENDING"

  if (!preload)
    session.allows[qtype] = true;

  if (!Object.values(session.types).includes("PENDING"))
    return Promise.resolve(session)

  const callback = v => {
    session.types[qtype] = "DONE";
    if (!Object.values(session.types).includes("PENDING")) {
      session.resolv(session);
    }
  }

  const reject_wraper = v => {
    delete session.types[qtype]
    session.reject();
  }

  dnsDispatchQuery(session, query).then(callback, reject_wraper);

  return session.promise;
}

function preference(json, prefMaps) {
  let pref = INVALIDE_PREFERENE, best = INVALIDE_PREFERENE;

  if (json && json.answers) {
    for (item of json.answers) {
      if (item.type == 'AAAA') {
        // LOG_DEBUG("item6.name " + item.name + " table=" + table.lookup6(item.data) + " data=" + item.data);
        pref = prefMaps[table.lookup6(item.data)];
        if (pref < best) best = pref;
      } else if (item.type == 'A') {
        // LOG_DEBUG("item4.name " + item.name + " table=" + table.lookup4(item.data) + " data=" + item.data);
        pref = prefMaps[table.lookup4(item.data)];
        if (pref < best) best = pref;
      }
    }
  }

  return best;
}

function isDualStackDomain(domain) {
  const host = domain.toLowerCase();
  const categories = ["www.gstatic.com", "connectivitycheck.gstatic.com", "mtalk.google.com", "google.com"];

  return categories.includes(host);
}

function cacheFilter(session) {
  let ipv4Far = session.farCaches["A"];
  let ipv6Far = session.farCaches["AAAA"];

  let ipv4Near = session.nearCaches["A"];
  let ipv6Near = session.nearCaches["AAAA"];

  let ipv4Record = null, ipv6Record = null;
  let ipv4Pref = INVALIDE_PREFERENE, ipv6Pref = INVALIDE_PREFERENE, mainPref = INVALIDE_PREFERENE;
  const isNearGood = !DETECHCACHE[session.key] || DETECHCACHE[session.key] != "cachedBad";

  let pref = preference(ipv6Near, [IPV6_NEAR_PREFERENE, INVALIDE_PREFERENE]);
  if (pref <= ipv6Pref && isNearGood) {
    ipv6Pref = pref;
    ipv6Record = ipv6Near;
  }
  // ipv6Near.answers.map(i => LOG_DEBUG("near " + JSON.stringify(i)));

  pref = preference(ipv6Far, [INVALIDE_PREFERENE, IPV6_FAR_PREFERENE]);
  if (pref <= ipv6Pref) {
    ipv6Pref = pref;
    ipv6Record = ipv6Far;
  }
  // ipv6Far.answers.map(i => LOG_DEBUG("far_ " + JSON.stringify(i)));

  pref = preference(ipv4Near, [IPV4_NEAR_PREFERENE, INVALIDE_PREFERENE]);
  if (pref <= ipv4Pref && isNearGood) {
    ipv4Pref = pref;
    ipv4Record = ipv4Near;
  }

  pref = preference(ipv4Far, [INVALIDE_PREFERENE, IPV4_FAR_PREFERENE]);
  if (pref <= ipv4Pref) {
    ipv4Pref = pref;
    ipv4Record = ipv4Far;
  }

  pref = preference(ipv4Far, [INVALIDE_PREFERENE, NAT64_FAR_PREFERENE]);
  if (pref <= ipv6Pref && session.allows['A']) {
    ipv6Pref = pref;
    ipv6Record = ipv4Far;
  }

  pref = preference(ipv4Near, [NAT64_NEAR_PREFERENE, INVALIDE_PREFERENE]);
  if (pref <= ipv6Pref && isNearGood && session.allows['A']) {
    ipv6Pref = pref;
    ipv6Record = ipv4Near;
  }

  let results = {ipv4: [], ipv6: []};
  mainPref = ipv4Pref > ipv6Pref? ipv6Pref: ipv4Pref;

  LOG_DEBUG("key = " + session.key + " ipv4pref=" + ipv4Pref + " ipv6pref=" + ipv6Pref + " mainpref=" + mainPref);
  if (mainPref == INVALIDE_PREFERENE) {
    return results;
  }

  if (ipv4Pref <= mainPref || (isDualStackDomain(session.key) && ipv4Record)) {
    ipv4Record.answers.map(item => LOG_DEBUG("ipv4=" + JSON.stringify(item)));
    for (let item of ipv4Record.answers) {
      let newitem = Object.assign({}, item);
      results.ipv4.push(newitem);
    }
  }

  results.ipv6 = [];
  if (ipv6Pref <= mainPref || (isDualStackDomain(session.key) && ipv6Record)) {
    ipv6Record.answers.map(item => LOG_DEBUG("ipv6=" + JSON.stringify(item)));
    for (let item of ipv6Record.answers) {
      let newitem = Object.assign({}, item);
      results.ipv6.push(newitem);
    }
  }

  return results;
}

function sendSegment(socket, segment) {
  let b = Buffer.alloc(2);
  b.writeUInt16BE(segment.length);

  socket.write(b);
  socket.write(segment);
}

async function* handleRequest(socket) {

  let total = 0;
  let segsize = 0;
  let buffers = [];
  let ended   = false;

  let onTimeout = v => {
    if (!ended) {
      ended = true;
    } else {
      socket.destroy();
    }
  };

  let timer = setInterval(onTimeout, 600000);

  LOG_DEBUG('FROM ' + socket.remoteAddress + " port=" + socket.remotePort);
try {
  for await (const data of socket) {
    total += data.length;
    buffers.push(data);

    LOG_DEBUG('FROM ' + socket.remoteAddress + " port=" + socket.remotePort + " data=" + data.length);
    ended = false;
    while (total >= 2) {

      if (buffers[0].length < 2) {
        const stream = Buffer.concat(buffers);
        buffers = [stream];
      }

      segsize = buffers[0].readUInt16BE();
      if (segsize + 2 > total) {
        break;
      }

      const stream = Buffer.concat(buffers);

      buffers = [];
      total -= (segsize + 2);

      if (total > 0) {
        let lastbuf = stream.slice(segsize + 2);
        buffers.push(lastbuf);
      }

      const fragment = stream.slice(2, segsize + 2);

      const query = dnsp.decode(fragment);
      if (query.questions[0].type == 'AAAA') {
        const promise = dnsFetchQuery(fragment);
        preNat64Load(query).catch(v => {});
        yield [promise, query];
      } else if (query.questions[0].type == 'A') {
        const promise = dnsFetchQuery(fragment);
        yield [promise, query];
      } else {
	let  session = {nearCaches: {}, farCaches: {}, key: query.questions[0].name.toLowerCase(), allows: {}, types: {}};
        const promise = dnsDispatchQuery(session, query);
        yield [promise, query];
      }

      ended = false;
    }
  }
} catch (e) {
  LOG_ERROR(`read exception ${e}`);
}

  LOG_DEBUG("session ended");
  if (!ended) socket.end();
  clearInterval(timer);
  // socket.end();
}

const NAT64_PREFIX = "64:ff9b::";

function formatAnswer6(answers, domain) {
  let key = domain.toLowerCase();

  const cb = item => {
    let answer = Object.assign({}, item);

    if (item.name.toLowerCase() == key) {
      answer.name = domain;
    }

    if (item.type == 'A') {
      answer.data = NAT64_PREFIX + item.data;
      answer.type = "AAAA";
    }

    return answer;
  };

  return answers.map(cb);
}

function formatAnswer(answers, domain) {
  let key = domain.toLowerCase();

  const cb = item => {
    let answer = Object.assign({}, item);

    if (item.name.toLowerCase() == key) {
      answer.name = domain;
    }

    return answer;
  };

  return answers.map(cb);
}

let FACING_PROMISE = null;
const FACING_SERVER = "crypto.cloudflare.com";

function loadFacingResults(session, results) {
   if (session.facingResult == "FAILURE") return results;

  const HOSTS = ["www.v2ex.com", "cdn.v2ex.com", "v2ex.com"];
  // const facingServer = HOSTS.includes(session.key)? "crypto.cloudflare.com": FACING_SERVER;
  const facingServer = HOSTS.includes(session.key)? FACING_SERVER: FACING_SERVER;
 
   // session.facingResult = "SUCCESS";

  const query4 = {
    type: 'query',
    id: 1,
    flags: dnsp.RECURSION_DESIRED,
    questions: [{
      type: 'A',
      name: facingServer
    }]
  }

  const query6 = {
    type: 'query',
    id: 11,
    flags: dnsp.RECURSION_DESIRED,
    questions: [{
      type: 'AAAA',
      name: facingServer
    }]
  }

  const queryHttps = {
    type: 'query',
    id: 111,
    flags: dnsp.RECURSION_DESIRED,
    questions: [{
      type: 'UNKNOWN_65',
      name: facingServer
    }]
  }

  const v4 = dnsFetchQuery(dnsp.encode(query4), true);
  const v6 = dnsFetchQuery(dnsp.encode(query6), true);
  const https = dnsFetchQuery(dnsp.encode(queryHttps), true);

  const checkFacingResult = v => {
    /*
      LOG_DEBUG("facing v4 is " + JSON.stringify(v[0]));
      LOG_DEBUG("facing v6 is " + JSON.stringify(v[1]));
      LOG_DEBUG("facing hs is " + JSON.stringify(v[2]));
      */

    const resultsHttps = v[2];
    if (resultsHttps.farCaches['UNKNOWN_65'].answers.length == 0) return results;

    session.facingResult = "DONE";
    const retvalues = cacheFilter(resultsHttps);

    retvalues.farCaches = resultsHttps.farCaches;
    return  retvalues;
  }

  return Promise.all([v4, v6, https]).then(checkFacingResult, v => session.facingResult = "FAILURE");
}

function preNat64Load(query) {
  const query64 = {
    type: 'query',
    id: 1,
    flags: dnsp.RECURSION_DESIRED,
    questions: [{
      type: 'A',
      name: query.questions[0].name
    }]
  }

  return dnsFetchQuery(dnsp.encode(query64), false);
}

async function streamHandler(socket) {
  const generator = handleRequest(socket);

  const backcall = (session, query) => {
    const qtype   = query.questions[0].type;
    if (qtype == 'AAAA') {
      const results = cacheFilter(session);

      query.answers = formatAnswer6(results.ipv6, query.questions[0].name);
      query.type = "response";

      LOG_DEBUG("R: IPV6 " + JSON.stringify(results.ipv6));
      sendSegment(socket, dnsp.encode(query));
    } else if (qtype == 'A') {
      const results = cacheFilter(session);

      query.answers = formatAnswer(results.ipv4, query.questions[0].name);
      query.type = "response";

      LOG_DEBUG("R: IPV4 " + JSON.stringify(results.ipv4));
      sendSegment(socket, dnsp.encode(query));
    } else {
      LOG_DEBUG("R: OUTE ");
      query.answers = session.farCaches[qtype].answers;
      query.type = "response";
      sendSegment(socket, dnsp.encode(query));
    }
  }

  let pendings = []

  const flush_pendings = (session, one) => {
    one.session = session
    one.state   = "DONE"
    one.aborted = false

    while (pendings.length > 0 && pendings[0].state == "DONE") {
      let two = pendings.shift()
      two.aborted || backcall(two.session, two.query)
    }
  }

  const query_exception = one => {
    LOG_ERROR("TODO:XXX failure " + JSON.stringify(one.query))
    one.state   = "DONE"
    one.aborted = true

    while (pendings.length > 0 && pendings[0].state == "DONE") {
      let two = pendings.shift()
      two.aborted || backcall(two.session, two.query)
    }
  }

  for await (const [promise, query] of generator) {
    const one = {query: query, state: "PENDING", aborted: false}
    pendings.push(one)
    promise.then(session => flush_pendings(session, one), v => query_exception(one))
  }
}

const server = tls.createServer(options, (socket) => {
  LOG_DEBUG('server connected', socket.authorized ? 'authorized' : 'unauthorized');
  const address = socket.remoteAddress;
  socket.on("error", e => LOG_DEBUG("tls error " + e));
  socket.on("close", e => socket.end());

  const _catched = e => {
    LOG_ERROR("e = " + e);
    LOG_ERROR(" " + e.stack);
  };

  streamHandler(socket).catch(_catched);
});


server.listen(853, "127.9.9.9", () => {
  LOG_DEBUG('server bound');
});

const tcpserver = net.createServer(options, async (socket) => {
  const address = socket.remoteAddress;
  socket.on("error", e => LOG_DEBUG("tcp error " + e));
  socket.on("close", e => socket.end());

  const _catched = e => {
    LOG_ERROR("e = " + e);
    LOG_ERROR(" " + e.stack);
  };

  streamHandler(socket).catch(_catched);
});

tcpserver.listen(8853, () => {
  LOG_DEBUG('server bound');
});

function requestEnd(res, body, status = 200, headers = {}) {
  res.statusCode = status;
  for (const [k, v] of Object.entries(headers))
    res.setHeader(k, v);
  res.end(body);
  return;
}

let cacheGoogleDomains = {};
const GOOGLE_PORT = 53;
const GOOGLE_NAME_SERVER = "::ffff:216.239.34.10";

function isGoogleDomain(fqdn, answsers)
{
    if (isDualStackDomain(fqdn) || !answsers.some(item => { if (item.type == "A" || item.type == "AAAA") return table.isGoogleIp(item.data); })) {
        return Promise.resolve(false);
    }

    if (cacheGoogleDomains[fqdn]) {
        return cacheGoogleDomains[fqdn];
    }

    const client = dgram.createSocket('udp6');
    const detectMessage = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
    detectMessage.questions[0].name = fqdn;

    let google_answered = false;

    const google_query_msg = dnsp.encode(detectMessage);
    let google_out = v => google_answered || client.send(google_query_msg, GOOGLE_PORT, GOOGLE_NAME_SERVER, (err) => { LOG_DEBUG(` far send: ${err}`); });

    doAutoRetry(google_out);

    const onMessage = function(resolv) {
        return (segment, rinfo) => {
            let msg = dnsp.decode(segment);
            LOG_DEBUG("isGoogle " + msg.rcode);
            google_answered = true;
            resolv(msg.rcode != "REFUSED");
        }
    }

    const testcb = (resolv, reject) => {
        client.on('error', reject);
        client.on('message', onMessage(resolv));
        setTimeout(reject, 3300);
    }

    const promise = new Promise(testcb);
    promise.finally(v => client.close());

    cacheGoogleDomains[fqdn] = promise;
    return cacheGoogleDomains[fqdn];
}

async function requestFetch(req, res) {
	const path = req.url;

	var dns_cb = b => {
		res.statusCode = 200;

		res.setHeader("Server", "cloudflare");
		res.setHeader("Date", new Date());
		res.setHeader("Content-Type", "application/dns-message");
		res.setHeader("Connection", "keep-alive");
		res.setHeader("Access-Control-Allow-Origin", "*");
		res.setHeader("Content-Length", b.length);

		res.end(b);
	};

	if (path.startsWith("/dns-query") && req.method === "GET") {
		LOG_DEBUG("path=" + path);
		if (path.includes("?")) {
			const pairs = querystring.parse(path.split("?")[1]);
			console.log("dns=" + pairs.dns);
			const fragment = Buffer.from(pairs.dns, 'base64');
			const query = dnsp.decode(fragment);
			const qtype = query.questions[0].type;
			let results = null, session = {nearCaches: {}, farCaches: {}};

			LOG_DEBUG("QUERY BY TYPE: " + query.questions[0].name + " TYPE=" + query.questions[0].type);

			switch(qtype) {
				case 'AAAA':
					session = await dnsFetchQuery(fragment);
					results = cacheFilter(session);

					query.type = "response";
					query.answers = formatAnswer6(results.ipv6, query.questions[0].name);

					LOG_DEBUG("RESPONSE6: " + query.questions[0].name);
					query.answers.map(item => LOG_DEBUG("out6=" + JSON.stringify(item)));
					dns_cb(dnsp.encode(query));
					break;

				case 'A':
					session = await dnsFetchQuery(fragment);
					results = cacheFilter(session);

					query.type = "response";
					query.answers = results.ipv4;
					query.answers = formatAnswer(results.ipv4, query.questions[0].name);

					LOG_DEBUG("RESPONSE4: " + query.questions[0].name);
					query.answers.map(item => LOG_DEBUG("out4=" + JSON.stringify(item)));
					dns_cb(dnsp.encode(query));
					break;

				default:
					let mydomain = query.questions[0].name;

					if (!results || !results.farCaches)
						results = await dnsDispatchQuery(session, query);

					query.answers = results.farCaches[qtype].answers;
					query.type = "response";

					LOG_DEBUG("RESPONSE: " + query.questions[0].name);
					query.answers.map(item => LOG_DEBUG("return=" + JSON.stringify(item)));
					dns_cb(dnsp.encode(query));
					break;
			}

			return;
		}

		res.statusCode = 403;

		res.setHeader("Server", "cloudflare");
		res.setHeader("Date", new Date());
		res.setHeader("Content-Type", "application/dns-message");
		res.setHeader("Connection", "keep-alive");
		res.setHeader("Access-Control-Allow-Origin", "*");
		res.setHeader("Content-Length", 0);

		res.end();
		return;
	}

	if (path.startsWith("/dns-query") && req.method === "POST") {

		const buffers = [];
		for await (const data of req)
			buffers.push(data);
		const fragment = Buffer.concat(buffers);

		const query = dnsp.decode(fragment);
		const qtype = query.questions[0].type;
		let results = null, session = {nearCaches: {}, farCaches: {}};

		let filter_facing_cb = item => {
			let newone = Object.assign({}, item);
			if (newone.name.toLowerCase() == FACING_SERVER) {
				newone.name = query.questions[0].name;
				newone.ttl = 600;
			}
			return newone;
		};

		const fqdn = query.questions[0].name;
		let isTLSv3 = false;
		LOG_DEBUG("QUERY BY TYPE: " + query.questions[0].name + " TYPE=" + query.questions[0].type);

		switch(qtype) {
			case 'AAAA':
				await preNat64Load(query);
				session = await dnsFetchQuery(fragment);
				results = cacheFilter(session);

				query.type = "response";
				query.answers = formatAnswer6(results.ipv6, query.questions[0].name);

				isTLSv3 = await isGoogleDomain(fqdn, results.ipv4);
				if (isInjectHttps(fqdn) || isTLSv3) {
					results = await loadFacingResults(session, results);

					const ech_list = [];
					const filter_ech_ipv6 = item => {
						let answer = Object.assign({}, item);

						answer.name = query.questions[0].name;
						answer.ttl = 600;

						if (item.type == 'AAAA') {
							answer.data = item.data;
							ech_list.push(answer);
						} else if (item.type == 'A') {
							answer.data = NAT64_PREFIX + item.data;
							answer.type = "AAAA";
							ech_list.push(answer);
						}
					}

					if (session.facingResult == "DONE") {
						session.allows['A'] = true;
						// results = cacheFilter(session);
						// query.answers = formatAnswer6(results.ipv6, query.questions[0].name);
						results.ipv6.forEach(filter_ech_ipv6);
						query.answers = ech_list;
					}

					/*
					   query.answers = results.ipv6.map(filter_facing_cb);
					   query.answers.map(item => LOG_DEBUG("return6=" + JSON.stringify(item)));
					 */
				}


				LOG_DEBUG("RESPONSE6: " + query.questions[0].name);
				query.answers.map(item => LOG_DEBUG("out6=" + JSON.stringify(item)));
				dns_cb(dnsp.encode(query));
				break;

			case 'A':
				session = await dnsFetchQuery(fragment);
				results = cacheFilter(session);

				query.type = "response";
				query.answers = results.ipv4;
				query.answers = formatAnswer(results.ipv4, query.questions[0].name);

				isTLSv3 = await isGoogleDomain(fqdn, results.ipv4);
				if (isInjectHttps(fqdn) || isTLSv3) {
					results = await loadFacingResults(session, results);

					const outs = [];
					const cb = item => {
						let answer = Object.assign({}, item);
						answer.name = query.questions[0].name;
						answer.ttl = 600;

						if (item.type == "A") {
							answer.data = item.data;
							outs.push(answer);
						}
					}

					results.ipv4.forEach(cb);
					query.answers = outs;
					query.answers.map(item => LOG_DEBUG("return4=" + JSON.stringify(item)));
				}

				LOG_DEBUG("RESPONSE4: " + query.questions[0].name);
				query.answers.map(item => LOG_DEBUG("out4=" + JSON.stringify(item)));
				dns_cb(dnsp.encode(query));
				break;

			default:
				let mydomain = query.questions[0].name;

				if (qtype == "UNKNOWN_65") {
					const session64 = await preNat64Load(query);
					results = cacheFilter(session64);

					isTLSv3 = await isGoogleDomain(fqdn, results.ipv4);
					if (isTLSv3 || isInjectHttps(fqdn)) {
						results = await loadFacingResults(session64, results);
					}
				}

				if (!results || !results.farCaches)
					results = await dnsDispatchQuery(session, query);

				query.answers = results.farCaches[qtype].answers.map(filter_facing_cb);
				query.type = "response";

				let lastName = query.questions[0].name;
				const cb = item => {
					if (lastName != item.name)
						item.name = lastName;
					if (item.type == "CNAME")
						lastName = item.data;
				}
				query.answers.forEach(cb);

				LOG_DEBUG("RESPONSE: " + query.questions[0].name);
				query.answers.map(item => LOG_DEBUG("return=" + JSON.stringify(item)));
				dns_cb(dnsp.encode(query));
				break;
		}

		return;
	}

	if (path.startsWith("/proxy_config/")) {
		try {
			// var PROXY_COMMAND = "SOCKS 127.0.0.1:8888";
			var PROXY_COMMAND = "SOCKS 103.45.162.65:18881"
				var args = path.split("/");
			args.find(item => { if(item.startsWith("SOCKS")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
			args.find(item => { if(item.startsWith("PROXY")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
			args.find(item => { if(item.startsWith("HTTPS")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
			args.find(item => { if(item.startsWith("HTTP")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
			var data = fs.readFileSync("proxy.pac", 'utf8').replace("PROXY 127.0.0.1:8080", PROXY_COMMAND);
			var mimeType = "text/javascript";
			res.setHeader("Content-Type", mimeType);
			res.statusCode = 200;
			res.end(data); 
		} catch(e) {
			LOG_ERROR('XError:', e.stack);
			res.end();
		}
		return;
	}

	LOG_DEBUG("path=" + path + " method=" + req.method);
	for (const [k, v] of Object.entries(req.headers)) {
		LOG_DEBUG("" + k + "=" + v);
	}

	{
		let b = "<html/>"
			res.statusCode = 200;
		if (path.startsWith("/generate_204")) {
			res.statusCode = 204;
			b = "";
		}

		res.setHeader("Server", "cloudflare");
		res.setHeader("Date", new Date());
		res.setHeader("Content-Type", "text/html");
		res.setHeader("Connection", "keep-alive");
		res.setHeader("Access-Control-Allow-Origin", "*");
		res.setHeader("Content-Length", b.length);

		res.end(b);
	}
}

var httpserver = http.createServer(options, (req, res) => {

  const _catched = e => {
    LOG_DEBUG("e = " + e.stack);
    requestEnd(res, "", 500);
  };

  requestFetch(req, res).catch(_catched);
});

httpserver.listen(80);

assert(1 == table.lookup4("172.217.163.36"));
assert(1 == table.lookup6("2404:6800:4003:c02::6a"));
