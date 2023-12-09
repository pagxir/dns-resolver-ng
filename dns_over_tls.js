const tls = require('tls');
const fs = require('fs');
const net = require('net');
const http = require('http');
const dgram = require('dgram');
const table = require('./apnic-table-6');
const dnsp = require('dns-packet');
const assert = require('assert');

const options = {
  key: fs.readFileSync('certificate/tls.key'),
  cert: fs.readFileSync('certificate/fullchain.cer'),
  requestCert: false,
  ca: [ fs.readFileSync('certificate/ca.cer') ]
};

let dumpFirst = 0;
// if (table.lookup());

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

function dnsSendQuery(session, client, message) {
  let near_answered = false;
  let far_answered = false;
  let fake_answered = false, fake_request = false;

  const onMessage = function(resolv) {
    return (segment, rinfo) => {
      let msg = dnsp.decode(segment);
      // console.log("response " + JSON.stringify(msg));
      // console.log("rinfo " + rinfo.address + " fast " + NEAR_SERVER + " slow " + FAR_SERVER);

      const qname = msg.questions[0].name;
      if (fake_request && qname.endsWith(DETECT_DOMAIN_SUFFIEX)) {

        const originName = qname.replace(DETECT_DOMAIN_SUFFIEX, "").toLowerCase();

        if (msg.answers.find(item => item.type == 'A' && item.data == "127.127.127.127")) {
          console.log("cachedOK " + originName);
          DETECHCACHE[originName] = "cachedOK";
        } else if (msg.answers.find(item => item.type == 'A' && item.data != "127.127.127.127")) {
          console.log("cachedBad " + originName);
          DETECHCACHE[originName] = "cachedBad";
        }

        fake_answered = true;
      } else if (rinfo.address == NEAR_SERVER && !near_answered) {
        near_answered = true;
        session.nearCaches[msg.questions[0].type] = msg;
        /*"Ok":"cachedOK":"cachedBad": */
        if (getDetectStatus(msg) == "Chaos") {
          console.log("detect start " + qname);
          const detectMessage = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
          detectMessage.questions[0].name = qname + DETECT_DOMAIN_SUFFIEX;
          fake_request = true;

          const oil_msg = dnsp.encode(detectMessage);
          let oil_out = v => fake_answered || client.send(oil_msg, FAR_PORT, FAR_SERVER, (err) => {  });

          oil_out();
          const oil_timeout = setTimeout(oil_out, 300);
        }
      } else if (rinfo.address == FAR_SERVER && !fake_answered) {
        session.farCaches[msg.questions[0].type] = msg;
        far_answered = true;
      }

      // console.log("slow_answer " + far_answered + " fast_answer " + near_answered);
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
  let far_out = v => far_answered || client.send(far_msg, FAR_PORT, FAR_SERVER, (err) => { console.log(` far send: ${qname} ${type} ${err}`); });

  dnsSetClientSubnet(msg, "117.144.103.197");
  const near_msg = dnsp.encode(msg);
  let near_out = v => near_answered || client.send(near_msg, NEAR_PORT, NEAR_SERVER, (err) => { console.log(`near send: ${qname} ${type} ${err}`); });

  near_out();
  const near_timeout = setTimeout(near_out, 300);

  far_out();
  const far_timeout = setTimeout(far_out, 300);

  const cb = (resolv, reject) => {
    client.on('error', reject);
    client.on('message', onMessage(resolv));
    const timer = setTimeout(reject, 3300);
  };

  return new Promise(cb);
}

function dnsDispatchQuery(session, message) {
  const client = dgram.createSocket('udp6');

  console.log("QUERY " + JSON.stringify(message.questions[0]));
  return dnsSendQuery(session, client, message).finally(v => client.close());
}

let OLD_SESSION = {};
let NEW_SESSION = {};

let SESSION = OLD_SESSION;
let old_new_stamp = new Date().getTime();

function sessionCallback(resolv, reject, query) {
  let promises = [];
  const key = query.questions[0].name.toLowerCase();
  let session = {nearCaches: {}, farCaches: {}, "key": key};

  let newq = dnsp.decode(dnsp.encode(query));
  let question0 = Object.assign({}, newq.questions[0]); 

  if (query.questions[0].type == 'AAAA') {
    question0.type = 'A';
    newq.questions = [question0];

    promises.push(dnsDispatchQuery(session, newq));
    promises.push(dnsDispatchQuery(session, query));
  } else if (query.questions[0].type == 'A') {
    let question0 = Object.assign({}, newq.questions[0]); 
    question0.type = 'AAAA';
    newq.questions = [question0];

    promises.push(dnsDispatchQuery(session, newq));
    promises.push(dnsDispatchQuery(session, query));
  }

  Promise.all(promises).then(v => resolv(session), reject);
};

function isInjectHttps(domain)
{
   let lowerDomain = domain.toLowerCase();

   const categories = ["www.v2ex.com", "cdn.v2ex.com", "www.quora.com"];

   return categories.includes(lowerDomain);
}

function dnsFetchQuery(fragment) {

  const query = dnsp.decode(fragment);
  const domain = query.questions[0].name;
  const key = domain.toLowerCase();

  const stamp = new Date().getTime();

  if (old_new_stamp + 5000 < stamp) {
    if (SESSION === OLD_SESSION) {
      SESSION = NEW_SESSION = {};
      old_new_stamp = stamp;
    } else if (SESSION === NEW_SESSION) {
      SESSION = OLD_SESSION = {};
      old_new_stamp = stamp;
    }
    console.log("old session select " + (SESSION === OLD_SESSION));
    console.log("new session select " + (SESSION === NEW_SESSION));
  }

  if (OLD_SESSION[key]) {
    SESSION == OLD_SESSION || (SESSION[key] = OLD_SESSION[key]);
    return OLD_SESSION[key];
  }

  if (NEW_SESSION[key]) {
    SESSION == NEW_SESSION || (SESSION[key] = NEW_SESSION[key]);
    return NEW_SESSION[key];
  }

  const cb = (resolv, reject) => sessionCallback(resolv, reject, query);
  SESSION[key] = new Promise(cb);
  return SESSION[key];
}

function preference(json, prefMaps) {
  let pref = INVALIDE_PREFERENE, best = INVALIDE_PREFERENE;

  if (json && json.answers) {
    for (item of json.answers) {
      if (item.type == 'AAAA') {
        // console.log("item6.name " + item.name + " table=" + table.lookup6(item.data) + " data=" + item.data);
        pref = prefMaps[table.lookup6(item.data)];
        if (pref < best) best = pref;
      } else if (item.type == 'A') {
        // console.log("item4.name " + item.name + " table=" + table.lookup4(item.data) + " data=" + item.data);
        pref = prefMaps[table.lookup4(item.data)];
        if (pref < best) best = pref;
      }
    }
  }

  return best;
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
  // ipv6Near.answers.map(i => console.log("near " + JSON.stringify(i)));

  pref = preference(ipv6Far, [INVALIDE_PREFERENE, IPV6_FAR_PREFERENE]);
  if (pref <= ipv6Pref) {
    ipv6Pref = pref;
    ipv6Record = ipv6Far;
  }
  // ipv6Far.answers.map(i => console.log("far_ " + JSON.stringify(i)));

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
  if (pref <= ipv6Pref) {
    ipv6Pref = pref;
    ipv6Record = ipv4Far;
  }

  pref = preference(ipv4Near, [NAT64_NEAR_PREFERENE, INVALIDE_PREFERENE]);
  if (pref <= ipv6Pref && isNearGood) {
    ipv6Pref = pref;
    ipv6Record = ipv4Near;
  }

  let results = {ipv4: [], ipv6: []};
  mainPref = ipv4Pref > ipv6Pref? ipv6Pref: ipv4Pref;
  console.log("key = " + session.key + " ipv4pref=" + ipv4Pref + " ipv6pref=" + ipv6Pref + " mainpref=" + mainPref);

  if (mainPref == INVALIDE_PREFERENE) {
	return results;
  }

  if (ipv4Pref <= mainPref) {
    ipv4Record.answers.map(item => console.log("ipv4=" + JSON.stringify(item)));
    for (let item of ipv4Record.answers) {
      let newitem = Object.assign({}, item);
      results.ipv4.push(newitem);
    }
  }

  results.ipv6 = [];
  if (ipv6Pref <= mainPref) {
    ipv6Record.answers.map(item => console.log("ipv6=" + JSON.stringify(item)));
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
  let lastbuf = Buffer.alloc(0);
  let ended   = false;

  let onTimeout = v => {
    if (!ended) {
      ended = true;
    } else {
      socket.destroy();
    }
  };

  let timer = setInterval(onTimeout, 15000);

  console.log('FROM ' + socket.remoteAddress + " port=" + socket.remotePort);
  for await (const data of socket) {
    total += data.length;

    if (data.length < 2) {
      lastbuf += data;
    } else {
      buffers.push(data);
    }

    console.log('FROM ' + socket.remoteAddress + " port=" + socket.remotePort + " data=" + data.length);
    lastbuf = data;
    ended = false;
    while (total >= 2) {

      segsize = buffers[0].readUInt16BE();
      if (segsize + 2 > total) {
        break;
      }

      const stream = Buffer.concat(buffers);

      buffers = [];
      total -= (segsize + 2);
      lastbuf = Buffer.alloc(0);

      if (total > 0) {
        lastbuf = stream.slice(segsize + 2);
        buffers.push(lastbuf);
      }

      const fragment = stream.slice(2, segsize + 2);

      const query = dnsp.decode(fragment);
      if (query.questions[0].type == 'AAAA') {
        const promise = dnsFetchQuery(fragment);
        yield [promise, query];
      } else if (query.questions[0].type == 'A') {
        const promise = dnsFetchQuery(fragment);
        yield [promise, query];
      } else {
        yield [Promise.resolve(0), query];
      }

      ended = false;
    }
  }

  console.log("session ended");
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

async function streamHandler(socket) {
  const generator = handleRequest(socket);

  for await (const [promise, query] of generator) {
    const session = await promise;
    const qtype   = query.questions[0].type;
    if (qtype == 'AAAA') {
      const results = cacheFilter(session);

      query.answers = formatAnswer6(results.ipv6, query.questions[0].name);
      query.type = "response";

      console.log("R: IPV6 " + JSON.stringify(results.ipv6));
      sendSegment(socket, dnsp.encode(query));
    } else if (qtype == 'A') {
      const results = cacheFilter(session);

      query.answers = formatAnswer(results.ipv4, query.questions[0].name);
      query.type = "response";

      console.log("R: IPV4 " + JSON.stringify(results.ipv4));
      sendSegment(socket, dnsp.encode(query));
    } else {
      query.answers = [];
      query.type = "response";
      sendSegment(socket, dnsp.encode(query));
    }
  }
}

const server = tls.createServer(options, (socket) => {
  console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
  const address = socket.remoteAddress;
  socket.on("error", e => console.log("tls error " + e));
  socket.on("close", e => socket.end());

  const _catched = e => {
    console.log("e = " + JSON.stringify(e));
  };

  streamHandler(socket).catch(_catched);
});


server.listen(853, "127.9.9.9", () => {
  console.log('server bound');
});

const tcpserver = net.createServer(options, async (socket) => {
  const address = socket.remoteAddress;
  socket.on("error", e => console.log("tcp error " + e));
  socket.on("close", e => socket.end());

  const _catched = e => {
    console.log("e = " + JSON.stringify(e));
  };

  streamHandler(socket).catch(_catched);
});

tcpserver.listen(8853, () => {
  console.log('server bound');
});

function requestEnd(res, body, status = 200, headers = {}) {
  res.statusCode = status;
  for (const [k, v] of Object.entries(headers))
    res.setHeader(k, v);
  res.end(body);
  return;
}

function checkEncryptedClientHelloEnable(answsers) {
  const categories = ["www.v2ex.com", "cdn.v2ex.com", "www.quora.com"];
  return answsers.some(item => item.name.toLowerCase().includes("v2ex.com") || categories.includes(item.name.toLowerCase()));

  if (answsers.some(item => isInjectHttps(item.name.toLowerCase()))) {
    return true;
  }

  if (answsers.some(item => "www.gstatic.com" == (item.name.toLowerCase()))) {
    return false;
  }

  if (answsers.some(item => "google.com" == (item.name.toLowerCase()))) {
    return false;
  }

  return answsers.some(item => { if (item.type == "A" || item.type == "AAAA") return table.isGoogleIp(item.data); });
}

let FACING_PROMISE = null;
const FACING_SERVER = "crypto.cloudflare.com";

function facingHttpQuery() {
  let session = {nearCaches: {}, farCaches: {}};
  const facingQuery = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));

  facingQuery.questions[0].name = FACING_SERVER;
  facingQuery.questions[0].type = "UNKNOWN_65";

  return FACING_PROMISE = (FACING_PROMISE || dnsDispatchQuery(session, facingQuery));
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
      if (newone.name.toLowerCase() == FACING_SERVER)
        newone.name = query.questions[0].name;
      return newone;
    };

    console.log("QUERY BY TYPE: " + query.questions[0].name + " TYPE=" + query.questions[0].type);

    switch(qtype) {
      case 'AAAA':
        session = await dnsFetchQuery(fragment);
        results = cacheFilter(session);

        query.type = "response";
        query.answers = formatAnswer6(results.ipv6, query.questions[0].name);

        if (checkEncryptedClientHelloEnable(results.ipv4) || checkEncryptedClientHelloEnable(results.ipv6)) {
          let facingQuery = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
          facingQuery.questions[0].name = FACING_SERVER;
          facingSession = await dnsFetchQuery(dnsp.encode(facingQuery));

          results = cacheFilter(facingSession);
          query.answers = results.ipv6.map(filter_facing_cb);
          if (query.answers.some(item => item.type == "A")) query.answers = [];
          query.answers.map(item => console.log("return6=" + JSON.stringify(item)));
        }

        console.log("RESPONSE6: " + query.questions[0].name);
        query.answers.map(item => console.log("out6=" + JSON.stringify(item)));
        dns_cb(dnsp.encode(query));
        break;

      case 'A':
        session = await dnsFetchQuery(fragment);
        results = cacheFilter(session);

        query.type = "response";
        query.answers = results.ipv4;
        query.answers = formatAnswer(results.ipv4, query.questions[0].name);

        if (checkEncryptedClientHelloEnable(results.ipv4) || checkEncryptedClientHelloEnable(results.ipv6)) {
          let facingQuery = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
          facingQuery.questions[0].name = FACING_SERVER;
          facingSession = await dnsFetchQuery(dnsp.encode(facingQuery));

          results = cacheFilter(facingSession);
          query.answers = results.ipv4.map(filter_facing_cb);
          query.answers.map(item => console.log("return4=" + JSON.stringify(item)));
        }

        console.log("RESPONSE4: " + query.questions[0].name);
        query.answers.map(item => console.log("out4=" + JSON.stringify(item)));
        dns_cb(dnsp.encode(query));
        break;

      default:
        let mydomain = query.questions[0].name;

        if (qtype == "UNKNOWN_65") {

          const facingQuery = JSON.parse(JSON.stringify(DETECT_DOMAIN_JSON));
          facingQuery.questions[0].name = mydomain;

          let facingSession = await dnsFetchQuery(dnsp.encode(facingQuery));
          let facingResult = cacheFilter(facingSession);

          if (checkEncryptedClientHelloEnable(facingResult.ipv4) || checkEncryptedClientHelloEnable(facingResult.ipv6)) {
            results = await facingHttpQuery();
          }
        }

        if (!results || !results.farCaches)
          results = await dnsDispatchQuery(session, query);

        query.answers = results.farCaches[qtype].answers.map(filter_facing_cb);
        query.type = "response";

        console.log("RESPONSE: " + query.questions[0].name);
        query.answers.map(item => console.log("return=" + JSON.stringify(item)));
        dns_cb(dnsp.encode(query));
        break;
    }

    return;
  }

  console.log("path=" + path + " method=" + req.method);
  for (const [k, v] of Object.entries(req.headers)) {
    console.log("" + k + "=" + v);
  }

  throw "403 Forbidden";
}

var httpserver = http.createServer(options, (req, res) => {

  const _catched = e => {
    console.log("e = " + JSON.stringify(e));
    requestEnd(res, "", 500);
  };

  requestFetch(req, res).catch(_catched);
});

httpserver.listen(80);

assert(1 == table.lookup4("172.217.163.36"));
assert(1 == table.lookup6("2404:6800:4003:c02::6a"));
