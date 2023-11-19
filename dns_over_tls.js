const tls = require('tls');
const fs = require('fs');
const net = require('net');
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

const SLOW_PORT = 53;
const SLOW_SERVER = "::ffff:1.0.0.1";

const FAST_PORT = 53;
const FAST_SERVER = "::ffff:223.5.5.5";

const IPV4_FAST_PREFERENE = 1;
const IPV4_SLOW_PREFERENE = 4;

const IPV6_FAST_PREFERENE = 5;
const IPV6_SLOW_PREFERENE = 3;

const NAT64_FAST_PREFERENE = 8;
const NAT64_SLOW_PREFERENE = 3;

function preference(json, prefMaps) {
  let pref = 100, best = 100;

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

  return best;
}

function cacheFilter(session) {
  let ipv4Slow = session.slowCaches["A"];
  let ipv6Slow = session.slowCaches["AAAA"];

  let ipv4Fast = session.fastCaches["A"];
  let ipv6Fast = session.fastCaches["AAAA"];

  if (ipv6Slow && ipv4Slow && ipv4Fast && ipv6Fast) {
    // console.log("ipv6Slow: " + ipv6Slow.questions[0].name);
    // console.log("ipv6Fast: " + ipv6Fast.questions[0].name);

    // console.log("ipv4Slow: " + ipv4Slow.questions[0].name);
    // console.log("ipv4Fast: " + ipv4Fast.questions[0].name);

    if ((ipv4Fast.questions[0].name == ipv6Slow.questions[0].name)
      && (ipv4Fast.questions[0].name == ipv4Slow.questions[0].name)
      && (ipv4Slow.questions[0].name == ipv6Fast.questions[0].name)) {

      let ipv4Record = null, ipv6Record = null;
      let ipv4Pref = 100, ipv6Pref = 100, mainPref = 100;

      let pref = preference(ipv6Fast, [IPV6_FAST_PREFERENE, 100]);
      if (pref <= mainPref) {
	mainPref = pref;
        ipv6Pref = pref;
        ipv6Record = ipv6Fast;
      }

      pref = preference(ipv6Slow, [100, IPV6_SLOW_PREFERENE]);
      if (pref <= mainPref) {
	mainPref = pref;
        ipv6Pref = pref;
        ipv6Record = ipv6Slow;
      }

      pref = preference(ipv4Fast, [IPV4_FAST_PREFERENE, 100]);
      if (pref <= mainPref) {
	mainPref = pref;
        ipv4Pref = pref;
        ipv4Record = ipv4Fast;
      }

      pref = preference(ipv4Slow, [100, IPV4_SLOW_PREFERENE]);
      if (pref <= mainPref) {
	mainPref = pref;
        ipv4Pref = pref;
        ipv4Record = ipv4Slow;
      }

      pref = preference(ipv4Slow, [100, NAT64_SLOW_PREFERENE]);
      if (pref <= mainPref) {
	mainPref = pref;
        ipv6Pref = pref;
        ipv6Record = ipv4Slow;
      }

      pref = preference(ipv4Fast, [NAT64_FAST_PREFERENE, 100]);
      if (pref <= mainPref) {
	mainPref = pref;
        ipv6Pref = pref;
        ipv6Record = ipv4Fast;
      }

      console.log("domain=" + ipv4Slow.questions[0].name  + " mainPref=" + mainPref + " ipv6Pref=" + ipv6Pref + " ipv4Pref=" + ipv4Pref);
      session.ipv4 = [];
      if (ipv4Pref <= mainPref) {
	console.log("ipv4=" + JSON.stringify(ipv4Record.answers));
	for (let item of ipv4Record.answers) {
	  let newitem = Object.assign({}, item);
	  session.ipv4.push(newitem);
	}
      }

      session.ipv6 = [];
      if (ipv6Pref <= mainPref) {
	console.log("ipv6=" + JSON.stringify(ipv6Record.answers));
	for (let item of ipv6Record.answers) {
	  let newitem = Object.assign({}, item);
	  if (newitem.type == 'A') {
	    newitem.type = 'AAAA';
	    newitem.data = "64:ff9b::" + item.data;
	  }
	  session.ipv6.push(newitem);
	}
      }

      return true;
    }
  }

   return false;
}

function dnsSendQuery(session, client, message) {
  let slow_answered = false;
  let fast_answered = false;
  let slow_answers, fast_answers;

  const onMessage = function(resolv) {
    return (segment, rinfo) => {
      let msg = dnsp.decode(segment);
      // console.log("response " + JSON.stringify(msg));
      console.log("rinfo " + rinfo.address + " fast " + FAST_SERVER + " slow " + SLOW_SERVER);

      if (rinfo.address == SLOW_SERVER) {
	session.slowCaches[msg.questions[0].type] = msg;
	slow_answered = true;
	slow_answers = msg;
      }

      if (rinfo.address == FAST_SERVER) {
	session.fastCaches[msg.questions[0].type] = msg;
	fast_answered = true;
	fast_answers = msg;
      }

      console.log("slow_answer " + slow_answered + " fast_answer " + fast_answered);
      if (slow_answered && fast_answered) {
	if (msg.questions[0].type == 'AAAA' && cacheFilter(session)) {
	  resolv(segment);
	} else if (msg.questions[0].type == 'A' && cacheFilter(session)) {
	  resolv(segment);
	} else {
	  resolv(segment);
	}
      }
    }
  };

  const cb = (resolv, reject) => {
    client.on('error', reject);
    client.on('message', onMessage(resolv));
    client.timer = setTimeout(reject, 3300);
  };

  let msg = dnsNomalize(dnsp.decode(message));
  // dnsSetClientSubnet(msg, "103.70.115.29");
  let slow_msg = dnsp.encode(msg);
  let slow_out = v => slow_answered || client.send(slow_msg, SLOW_PORT, SLOW_SERVER, (err) => { console.log(`slow resend: ${err}`); });

  // let msg = dnsp.decode(message);
  dnsSetClientSubnet(msg, "117.144.103.197");
  let fast_msg = dnsp.encode(msg);
  let fast_out = v => fast_answered || client.send(fast_msg, FAST_PORT, FAST_SERVER, (err) => { console.log(`fast resend: ${err}`); });

  fast_out();
  setTimeout(slow_out, 300);

  slow_out();
  setTimeout(fast_out, 300);

  return new Promise(cb);
}

function dnsDispatchQuery(session, message) {
  const client = dgram.createSocket('udp6');

  const data = dnsp.decode(message);
  console.log("QUERY " + JSON.stringify(dnsp.decode(message).questions[0]));

  return dnsSendQuery(session, client, message).finally(v => client.close());
}

function sendSegment(socket, segment) {
  let b = Buffer.alloc(2);
  b.writeUInt16BE(segment.length);

  socket.write(b);
  socket.write(segment);
}

function cacheLookup(session, query) {
  const domain = query.questions[0].name;
  const qtype  = query.questions[0].type;

  if (qtype == 'AAAA' && session.ipv6) {
    for (let item of session.ipv6) {
      if (item.name == domain) {
	return session.ipv6;
      }
    }
  } else if (qtype == 'A' && session.ipv4) {
    for (let item of session.ipv4) {
      if (item.name == domain) {
	return session.ipv4;
      }
    }
  }

  return;
}

async function handleRequest(socket) {

  let total = 0;
  let segsize = 0;
  let buffers = [];
  let lastbuf = Buffer.alloc(0);
  let ended   = false;
  let session = {fastCaches: {}, slowCaches: {}};

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
      try {
	let promises = [];
	const query = dnsp.decode(fragment);
	const cache = cacheLookup(session, query);

	if (cache) {
	    let response = Object.assign({}, query);
	    response.type = "response";
	    response.answers = cache;

	    const msg = dnsp.encode(response);
	    sendSegment(socket, msg);
	} else if (query.questions[0].type == 'AAAA') {
	    let newq = Object.assign({}, query);
	    let question0 = Object.assign({}, newq.questions[0]); 
	    question0.type = 'A';
	    newq.questions = [question0];

	    promises.push(dnsDispatchQuery(session, dnsp.encode(newq)));
	    promises.push(dnsDispatchQuery(session, fragment));
	    await Promise.all(promises);

	    let response = Object.assign({}, query);
	    response.type = "response";
	    response.answers = session.ipv6;

	    const msg = dnsp.encode(response);
	    sendSegment(socket, msg);
	} else if (query.questions[0].type == 'A') {
	    let newq = Object.assign({}, query);
	    let question0 = Object.assign({}, newq.questions[0]); 
	    question0.type = 'AAAA';
	    newq.questions = [question0];

	    promises.push(dnsDispatchQuery(session, fragment));
	    promises.push(dnsDispatchQuery(session, dnsp.encode(newq)));
	    await Promise.all(promises);

	    let response = Object.assign({}, query);
	    response.type = "response";
	    response.answers = session.ipv4;

	    const msg = dnsp.encode(response);
	    sendSegment(socket, msg);
	} else {
	    const msg = await dnsDispatchQuery(session, fragment);
	    sendSegment(socket, msg);
	}
      } catch(e) {
	let msg = dnsp.decode(fragment);
	msg.type = "response";

	sendSegment(socket, dnsp.encode(msg));
	console.log("dns error " + e);
      }

      ended = false;
    }
  }

  console.log("session ended");
  if (!ended) socket.end();
  clearInterval(timer);
  // socket.end();
}

const server = tls.createServer(options, (socket) => {
  console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
  const address = socket.remoteAddress;
  socket.on("error", e => console.log("tls error " + e));
  socket.on("close", e => socket.end());
  handleRequest(socket);
});

server.listen(853, () => {
  console.log('server bound');
});

const tcpserver = net.createServer(options, (socket) => {
  const address = socket.remoteAddress;
  socket.on("error", e => console.log("tcp error " + e));
  socket.on("close", e => socket.end());
  handleRequest(socket);
});

tcpserver.listen(8853, () => {
  console.log('server bound');
});


assert(1 == table.lookup4("172.217.163.36"));
assert(1 == table.lookup6("2404:6800:4003:c02::6a"));
