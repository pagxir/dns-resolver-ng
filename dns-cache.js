import dgram from 'dgram';
import dnspacket from 'dns-packet';
import { NameServers, oilingMode } from './config.js';
import { lookup6, lookup4 } from './apnic-table-6.js';
import { LOG_ERROR, LOG_DEBUG } from './dns-utils.js';
import { dnsParse, dnsBuild, dnsObject } from './dns-utils.js';

function getSession(key) {

  const stamp = new Date().getTime();

  if (this.old_new_stamp + 540000 < stamp) {
    if (this.SESSION === this.OLD_SESSION) {
      this.SESSION = this.NEW_SESSION = {};
      this.old_new_stamp = stamp;
    } else if (this.SESSION === this.NEW_SESSION) {
      this.SESSION = this.OLD_SESSION = {};
      this.old_new_stamp = stamp;
    }
  }

  if (this.OLD_SESSION[key]) {
    this.SESSION == this.OLD_SESSION || (this.SESSION[key] = this.OLD_SESSION[key]);
    return this.OLD_SESSION[key];
  }

  if (this.NEW_SESSION[key]) {
    this.SESSION == this.NEW_SESSION || (this.SESSION[key] = this.NEW_SESSION[key]);
    return this.NEW_SESSION[key];
  }

  let session = {key: key, "AAAA": null, "A": null};
  this.SESSION[key] = session;

  return session;
}

function dnsCache(server, port) {
  this.OLD_SESSION = {};
  this.NEW_SESSION = {};
  this.SESSION = this.OLD_SESSION;
  this.old_new_stamp = new Date().getTime();
  this.getSession = getSession;

  this.dnsPort = port;
  this.dnsServer = server;
  this.dnsParse = dnsParse;
  this.dnsBuild = dnsBuild;

  return this;
}

const NS = NameServers;
const oilingCache = new dnsCache(NS.oiling.address, NS.oiling.port);
const primaryCache = new dnsCache(NS.nearby.address, NS.nearby.port);
const primaryCache6 = new dnsCache(NS.nearby6.address, NS.nearby6.port);

const secondaryCache = new dnsCache(NS.global.address, NS.global.port);
const secondaryCache6 = new dnsCache(NS.global6.address, NS.global6.port);

function dnsQueryInternal(cache, message) {
  let name = message.questions[0].name;
  let type = message.questions[0].type;

  let session = cache.getSession(name);

  if (session[type])
    return Promise.resolve(session[type]);

  const udp6 = dgram.createSocket('udp6');

  const cb = (resolv, reject) => {
    let timer = null;
    let timerReject = setTimeout(reject, 3000);

    const on_message = (data, rinfo) => {
      LOG_DEBUG("rinfo " + rinfo.address + " fast " + data.length);
      const result = cache.dnsParse(data);
      const fire = (result == dnsObject? reject: resolv);

      session[type] = result;
      clearTimeout(timerReject);
      clearTimeout(timer);
      fire(result);
    };

    const c = cache;
    const oil_msg = cache.dnsBuild(message);

    udp6.on("message", on_message.bind(udp6));
    const cb = i => udp6.send(oil_msg, c.dnsPort, c.dnsServer, LOG_DEBUG);

    timer = setTimeout(cb, 800);
    cb();
  };

  return new Promise(cb).finally(udp6.close.bind(udp6));
}

const NAT64_PREFIX = "64:ff9b::";

function dnsCheckOilingChina(message) {
   const checking = dnsQueryInternal(oilingCache, message);
   return checking.then(msg => msg.rcode != "REFUSED");
}

function dnsCheckOilingGlobal(message) {
  let message4 = Object.assign({}, message);
  let question4 = Object.assign({}, message.questions[0]);

  question4.name = question4.name + ".oil.cootail.com";
  question4.type = 'A';
  message4.questions = [question4];

  const checking = dnsQueryInternal(secondaryCache, message4);
  return checking.then(msg => !msg.answers.some(item => item.type == 'A' && item.data == "127.127.127.127"));
}

const dnsCheckOiling = oilingMode == "Global"? dnsCheckOilingGlobal: dnsCheckOilingChina;

function makeDnsMessage(name, type) {

  const dns0 = {
    questions: [
      {name, type}
    ],
    answers: [
    ]
  };

  return dns0;
}

function preloadResource(name, type, origin) {
  const dns = makeDnsMessage(name, type);

  dns.questions[0].name = name;
  dns.questions[0].type = type;

  if (name == 'mtalk.google.com' && type == 'AAAA') {
    const answer0 = {
      name: name,
      type: type,
      data: '2404:6800:4008:c1b::bc'
    };
    dns.answers.push(answer0);
    return dns;
  }

  const domainSuffix = [".cootail.com", "603030.xyz", "cachefiles.net"];
  const domainList = ["mtalk.google.com", "www.gstatic.com", "www.googleapis.cn", "connectivitycheck.gstatic.com"];

  if (domainSuffix.some(domain => name.includes(domain)))
    return dnsQueryInternal(primaryCache, origin);

  if (domainList.some(domain => name == domain))
    return dnsQueryInternal(primaryCache, origin);

  return undefined;
}

function AsiaWrap(message) {

  let question = Object.assign({}, message.questions[0]);
  question.type = 'AAAA';

  let last = Object.assign({}, message);
  last.questions = [question];

  last.answers = message.answers.map(item => {
    let o = Object.assign({}, item); 
    if (o.type == 'AAAA') {
      const parts = o.data.split(':');
      if (parts.length > 0 && parts[0].length > 0) {
        const prefix = parseInt(parts[0], 16);
        if ((prefix & 0xfff0) == 0x2400) {
          o.data = '1' + o.data.slice(1);
        } else if (prefix  == 0x2001) {
          o.data = '1' + o.data.slice(1);
        }
      }
    }
    return o;
  });

  return last;
}

function makeDns64(ipv4msg, ipv6msg, pref64)
{
  const upgradev6 = i => {
    const o = Object.assign({}, i);
    if (o.type == 'A') {
      o.data = NAT64_PREFIX + i.data;
      o.type = 'AAAA';
    }
    return o;
  };

  if (ipv4msg.answers.some(i => i.type == 'A') &&
    (pref64 || !ipv6msg.answers.some(i => i.type == 'AAAA'))) {
    const o = Object.assign({}, ipv6msg);
    o.answers = ipv4msg.answers.map(upgradev6);
    return o;
  }

  return AsiaWrap(ipv6msg);
}

function filterIpv6(results, isNat64, oiling) {
  let last = Object.assign({}, results[1]);
  last.answers = [];

  // results[1] = makeDns64(results[1], results[1], false);

  if (oiling) 
    return makeDns64(results[2], results[3], true);

  if (results[1].answers.some(item => item.type == 'AAAA' && !lookup6(item.data)))
    return results[1];

  if (results[0].answers.some(item => item.type == 'A' && !lookup4(item.data)))
    return last;

  if (results[2].answers.some(item => item.type == 'A'))
    return makeDns64(results[2], results[3], true);

  if (results[3].answers.some(item => item.type == 'AAAA'))
    return AsiaWrap(results[3]);

  return results[1];
}

function filterIpv4(results, useNat64, oiling) {

  if (!oiling && results[0].answers.some(item => item.type == 'A' && !lookup4(item.data))) {
    return results[0];
  }

  return results[2];
}

function dnsQueryImpl(message, useNat64) {
  const type = message.questions[0].type;
  const name = message.questions[0].name;

  const result = preloadResource(name, type, message);

  if (result) return Promise.resolve(result);

  if (type === 'A' || type == 'AAAA') {
    let message4 = Object.assign({}, message);
    let question4 = Object.assign({}, message.questions[0]);

    question4.type = 'A';
    message4.questions = [question4];

    let message6 = Object.assign({}, message);
    let question6 = Object.assign({}, message.questions[0]);

    question6.type = 'AAAA';
    message6.questions = [question6];

    let oiling6 = dnsCheckOiling(message6);
    let primary4 = dnsQueryInternal(primaryCache, message4);
    let primary6 = dnsQueryInternal(primaryCache6, message6);

    let secondary4 = dnsQueryInternal(secondaryCache, message4);
    let secondary6 = dnsQueryInternal(secondaryCache6, message6);

    let all = [primary4, primary6, secondary4, secondary6, oiling6];
    return Promise.all(all).then(results => {
      const filter = type == 'AAAA'? filterIpv6: filterIpv4;

      results[0].answers.map(item => LOG_DEBUG("  primary ipv4=" + JSON.stringify(item)));
      results[1].answers.map(item => LOG_DEBUG("  primary ipv6=" + JSON.stringify(item)));

      results[2].answers.map(item => LOG_DEBUG("secondary ipv4=" + JSON.stringify(item)));
      results[3].answers.map(item => LOG_DEBUG("secondary ipv6=" + JSON.stringify(item)));

      LOG_DEBUG("oiling=" + results[4]);

      return filter(results, false, results[4]);
    });
  }

  LOG_DEBUG("QUERY: " + JSON.stringify(message.questions));
  let primary = dnsQueryInternal(primaryCache, message);
  let secondary = dnsQueryInternal(secondaryCache, message);

  return Promise.any([secondary, primary]);
}

function dnsQuery(message) {

  const normalize = msg => {
    let last = Object.assign({}, msg);
    last.questions = message.questions;
    last.id = message.id;
    last.type = 'response';
    return last;
  };

  return dnsQueryImpl(message, true).then(normalize);
}

const dnsQuerySimple = dnsQuery;

function dnsQueryECH(message) {
  const type = message.questions[0].type;
  const name = message.questions[0].name;
  const facingName = "lamp.603030.xyz";

  let echMessage = Object.assign({}, message);
  switch (type) {
    case 'AAAA':
    case 'A':
    case 'UNKNOWN_65':
      echMessage.questions = [{name: facingName, type}];
      break;

    default:
      LOG_DEBUG("type = " + type);
      echMessage.questions = [{name, type}];
      break;
  }

  let echSecondary = dnsQueryInternal(secondaryCache, echMessage);

  let formatCb = result => {
    let o = Object.assign({}, result); 

    o.questions = message.questions;
    o.answers = result.answers.map(item => {
      let v = Object.assign({}, item);
      if (v.name == facingName) v.name = name;
      return v;
    });
    return o;
  };

  return echSecondary.then(formatCb);
}

export { dnsQuery, dnsQueryECH, dnsQuerySimple };
