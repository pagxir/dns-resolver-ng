import net from 'net';
import dgram from 'dgram';
import assert from 'assert';
import dnspacket from 'dns-packet';

import { dnsObject, dnsParse, dnsBuild } from './dns-utils.js';
import { LOG_ERROR, LOG_DEBUG } from './dns-utils.js';

let GLOBALCACHE = [
  {name: "", type: "NS", data: "a.root-servers.net"},
  {name: "a.root-servers.net", type: "A", data: "198.41.0.4"},
  {name: "a.root-servers.net", type: "AAAA", data: "2001:503:ba3e::2:30"}
];

function dnsNetworkLookup(message, c) {
  const udp6 = dgram.createSocket('udp6');

  const cb = (resolv, reject) => {
    let timer = null;
    let time1 = null;
    let timerReject = setTimeout(reject, 3000);

    const on_message = (data, rinfo) => {
      LOG_DEBUG("rinfo " + rinfo.address + " fast " + data.length);
      const result = dnsParse(data);
      const fire = (result == dnsObject? reject: resolv);

      clearTimeout(timerReject);
      clearTimeout(time1);
      clearTimeout(timer);
      fire(result);
    };

    const oil_msg = dnsBuild(message);

    udp6.on("message", on_message.bind(udp6));
    const cb = i => udp6.send(oil_msg, c.dnsPort, c.dnsServer, LOG_DEBUG);

    time1 = setTimeout(cb, 1800);
    timer = setTimeout(cb, 800);
    cb();
  };

  return new Promise(cb).finally(udp6.close.bind(udp6));
}

function getRandomInt(max) {
  return Math.floor(Math.random() * max);
}

function checkValidate(records, alias, type) {

	LOG_DEBUG("alias = " + alias);
	LOG_DEBUG("type = " + type);
	LOG_DEBUG("records = " + JSON.stringify(records));

  if (records.some(item => item.type == type)) {
    return true;
  }

  return false;
}

function dnsServerLock(server, LOCK) {

  if (!LOCK[server]) {
    LOCK[server] = true;
    return true;
  }

  return false;
}

function dnsServerUnlock(server, pool) {
   delete pool[server];
}

function dnsServerCheck(server, pool) {
  return pool[server];
}

function makeQuery(name, type) {
  const dnsObjectZero = {
    type: 'query',
    id: 26858,
    flags: dnspacket.RECURSION_DESIRED,
    questions: [{
      type: 'A',
      name: 'google.com'
    }],
    answers: [],
    additionals: [{
      name: ".",
      type: "OPT",
      udpPayloadSize: 1232,
      extendedRcode: 0,
      ednsVersion: 0,
      flags: 0,
      flag_do: false,
      options:[]
    }]
  };

  dnsObjectZero.questions[0].name = name;
  dnsObjectZero.questions[0].type = type;

  return dnsObjectZero;
}

async function dnsNetworkUpdate(alias, type, results, pool) {

  const message = makeQuery(alias, type);

  const temp = [];
  const updateCache = item => {
    temp.push(item);
  };

  for (let i = 0; i < results.length; i++) {
    if (results[i].type != 'A') continue;
    const result = await dnsNetworkLookup(message, {dnsServer: "::ffff:" + results[i].data, dnsPort: 53});
    LOG_DEBUG("dnsNetworkLookup: alias = " + alias);
    if (result.answers)
      result.answers.forEach(updateCache);

    if (result.authorities)
      result.authorities.forEach(updateCache);

    if (result.additionals)
      result.additionals.forEach(updateCache);

    if (result.flag_aa) {
      pool.authorized = result;
    };

    if (temp.length) {
      const arrayNew = GLOBALCACHE.filter(item => !temp.some(it => it.name == item.name && it.type == item.type));
      GLOBALCACHE = arrayNew.concat(temp);
      return true;
    }
  }

  return false;
}

function getDnsAlias(records, name) {

	LOG_DEBUG("getDnsAlias records " + JSON.stringify(records));
  if (records && records.length) {
    const last = records.at(-1);

    if (last.type == "CNAME")
      return last.data;
  }

  return name;
}

function quickCacheLookup(name, type) {
  const records = [];

  const cb = obj => {
    if (obj.name == name && obj.type == type)
      records.push(obj);
  };

  GLOBALCACHE.forEach(cb);
  LOG_DEBUG("name=" + name + " records=" + JSON.stringify(records));
  return records;
}

function dnsServerLookup(name) {
  let suffix = 0;
  let records = [];

  const cb = obj => {
    const domain = "." + name;
    const suffiz = "." + obj.name;

    if ((domain.endsWith(suffiz) || suffiz == '.')
      && obj.type == "NS" && suffix <= obj.name.length) {

      if (suffix != obj.name.length) {
	suffix = obj.name.length;
	records = [];
      }

      records.push(obj.data);
    }
  };

  GLOBALCACHE.forEach(cb);
  return records;
}

function dnsContains(alias, records) {
  return records.some(item => item.name == alias);
}

function dnsCacheLookup(name, type) {
  let records = [];
  let alias = name, results;

  do {
    results = quickCacheLookup(alias, type);
    if (results.length > 0) {
      records = records.concat(results);
      break;
    }

    results = quickCacheLookup(alias, "CNAME");
    if (results.length == 0) {
      break;
    }

    assert(results.length == 1);
    alias = results[0].data;
    if (dnsContains(alias, records)) {
      break;
    }

    records = records.concat(results);
  } while ( 1 );

	LOG_DEBUG("dnsCacheLookup: records= " + name + " return " + JSON.stringify(records));
  return records;
}

const lockGlobal = {}

const globalContext = {}
function registerGlobalCallback(context) {
  globalContext[context] = context;
}

function notifiyGlobalCallback(data) {
  Object.entries(globalContext).forEach((key, context) => {
    LOG_DEBUG("notifiyGlobalCallback " + data);
    context.resolv(data);
  });
}

function unregisterGlobalCallback(context) {
  delete globalContext[context];
}

async function dnsFullQuery(name, type, pool, request) {
  let alias = name;

  for ( ; ; ) {
    const records = dnsCacheLookup(alias, type);

    if (checkValidate(records, alias, type)) {
      return dnsCacheLookup(name, type);
    }

    const old = alias;
    alias = getDnsAlias(records, alias);
    if (request.authorized && old == alias) {
      return dnsCacheLookup(name, type);
    }

    let results = await dnsServerLookup(alias);
    delete pool.authorized;

    LOG_DEBUG("dnsFullQuery alias " + alias);
    LOG_DEBUG("dnsFullQuery results " + results);
    if (results && results.length) {
      let updated = false;
      const offset = getRandomInt(results.length);

      for (let index = 0; index < results.length; index++) {

        const refer = (index + offset) % results.length;
        const server = results[refer];

        const results0 = dnsCacheLookup(server, 'A');

        if (checkValidate(results0, server, 'A') && dnsServerLock(alias + server, pool)) {
          updated = await dnsNetworkUpdate(alias, type, results0, request);
	  if (updated && pool === lockGlobal)
	    notifiyGlobalCallback(name);
          if (updated) break;
        }
      }

      if (updated) continue;

      const context = {};
      context.birthtime = new Date();
      const promise = new Promise((resolv, reject) => {
	context.resolv = resolv;
	context.reject = reject;
      });

      LOG_DEBUG("dnsFullQuery start network lookup " + alias);
      for (let index = 0; index < results.length; index++) {
        const refer = (index + offset) % results.length;
        const server = results[refer];

	if (dnsServerCheck(alias + server, pool)) {
	  continue;
	}

        LOG_DEBUG("dnsFullQuery network lookup " + server);
	if (dnsServerLock(server, lockGlobal)) {
	  delete lockGlobal.authorized;
	  const results0 = await dnsFullQuery(server, 'A', lockGlobal, {});
	  dnsServerUnlock(server, lockGlobal);
        LOG_DEBUG("dnsFullQuery network return " + results0);
	  updated = results0.length > 0;
          if (updated) break;
	} else if (!context.waiting) {
	  registerGlobalCallback(context);
	  context.waiting = true;
	}
      }

      if (updated) {
	if (context.waiting)
	  unregisterGlobalCallback(context);
	continue;
      }

      if (context.waiting) {
	await promise;
	unregisterGlobalCallback(context);
	continue;
      }
    }

    Object.entries(pool).forEach((key, context) => LOG_DEBUG("FAILURE Lookup " + key));
    LOG_DEBUG("failure lookup");
    return dnsCacheLookup(name, type);
  }
}

async function onDnsQuery(segment, rinfo) {
  LOG_DEBUG("UDP SERVER rinfo " + rinfo.address);

  try {
    const query = dnsParse(segment);
    const name = query.questions[0].name;
    const type = query.questions[0].type;
    const context = {};

	  LOG_DEBUG("query: " + JSON.stringify(query));

    const result = await dnsFullQuery(name, type, context, context);
    query.answers = result;
    query.type = "response";
    if (context.authorized)
	query.flags = context.authorized.flags;
    let out_segment = dnsBuild(query);

    this.send(out_segment, rinfo.port, rinfo.address, (err) => { LOG_ERROR("send error " + err); });
  } catch (e) {
    LOG_ERROR("UDP FAILURE " + e);
    e && LOG_ERROR(e.stack);
  }
}

function onFailure(e) {
  LOG_ERROR(`onFailure ${e}`);
}

const udp6 = dgram.createSocket('udp6');
udp6.bind(5321, '::ffff:127.9.9.9');
udp6.on('message', onDnsQuery.bind(udp6));
udp6.on('error', onFailure);

LOG_DEBUG(dnsServerLookup("www.baidu.com"));
LOG_DEBUG(dnsCacheLookup("a.root-servers.net", 'A'));
LOG_DEBUG(quickCacheLookup("a.root-servers.net", 'A'));
