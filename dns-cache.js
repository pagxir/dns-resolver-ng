import dgram from 'dgram';
import dnspacket from 'dns-packet';
import {lookup6, lookup4} from './apnic-table-6.js';
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

  this.FAR_PORT = port;
  this.FAR_SERVER = server;
  this.dnsParse = dnsParse;
  this.dnsBuild = dnsBuild;

  return this;
}

function checkNat64(name) {
  const key = name.toLowerCase();

  if (key == "mtalk.google.com") return false;
  if (key == "www.gstatic.com") return false;
  if (key == "www.googleapis.cn") return false;
  if (key == "connectivitycheck.gstatic.com") return false;

  return !(key.includes(".cootail.com") || key.includes("603030.xyz") || key.includes("cachefiles.net"));
}

function makeDnsCache64(cache) {
  let dore = {};

  dore.cache = cache;
  dore.getSession = name => cache.getSession(name);
  dore.FAR_PORT = cache.FAR_PORT;
  dore.FAR_SERVER = cache.FAR_SERVER;

  dore.dnsParse = data => {
    let origin = dnsParse(data);
    let question = Object.assign({}, origin.questions[0]);
    question.type = 'AAAA';
    if (!checkNat64(question.name)) return origin;

    let message = Object.assign({}, origin);
    message.questions = [question];

    message.answers = origin.answers.map(item => {
      let o = Object.assign({}, item); 
      if (o.type == 'A') {
	o.type = 'AAAA';
	o.data = NAT64_PREFIX + o.data;
      }
      return o;
    });

    return message;
  };

  dore.dnsBuild = message => {
    let question = Object.assign({}, message.questions[0]);
    if (checkNat64(question.name))
      question.type = 'A';

    let dataview = Object.assign({}, message);
    dataview.questions = [question];

    return dnsBuild(dataview);
  };

  return dore;
}

const oilingCache = new dnsCache("::ffff:202.12.30.131", 53);
const primaryCache = new dnsCache("::ffff:192.168.1.1", 53);
const primaryCache6 = new dnsCache("2001:4860:4860::8888", 53);
const secondaryCache = new dnsCache("64:ff9b::101:101", 53);
const secondaryCache6 = makeDnsCache64(secondaryCache);

function dnsQueryInternal(cache, message) {
  let name = message.questions[0].name;
  let type = message.questions[0].type;

  let session = cache.getSession(name);

  if (session[type]) {
    let result = Object.assign({}, session[type]);
    result.id = message.id;
    result.questions = message.questions;
    LOG_ERROR(`fetch from cache ${name}`);
    return Promise.resolve(result);
  }

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
    const cb = i => udp6.send(oil_msg, c.FAR_PORT, c.FAR_SERVER, LOG_DEBUG);

    timer = setTimeout(cb, 800);
    cb();
  };

  return new Promise(cb).finally(udp6.close.bind(udp6));
}

const NAT64_PREFIX = "64:ff9b::";

function dnsCheckOiling(message) {
  const checking = dnsQueryInternal(oilingCache, message);
  return checking.then(msg => msg.rcode != "REFUSED");
}

function AsiaWrap(message) {
    if (!checkNat64(message.questions[0].name)) return message;

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

function filterIpv6(results, isNat64, oiling) {
  let last = Object.assign({}, results[1]);
  last.answers = [];

  if (oiling) 
    return AsiaWrap(results[3]);

  if (results[1].answers.some(item => item.type == 'AAAA' && !lookup6(item.data)))
    return results[1];

  if (results[0].answers.some(item => item.type == 'A' && !lookup4(item.data)))
    return last;

  if (results[3].answers.some(item => item.type == 'AAAA'))
    return AsiaWrap(results[3]);

  return AsiaWrap(results[1]);
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

      return filter(results, useNat64 && checkNat64(name), results[4]);
    });
  }

  LOG_DEBUG("QUERY: " + JSON.stringify(message.questions));
  let primary = dnsQueryInternal(primaryCache, message);
  let secondary = dnsQueryInternal(secondaryCache, message);
  return Promise.any([secondary, primary]);
}

const dnsQuery = message => dnsQueryImpl(message, true);
const dnsQuerySimple = message => dnsQueryImpl(message, false);

function dnsQueryECH(message) {
  const type = message.questions[0].type;
  const name = message.questions[0].name;
  const facingName = "facing.cootail.com";

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
