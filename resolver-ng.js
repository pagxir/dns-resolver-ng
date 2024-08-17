import fs from 'fs';
import tls from 'tls';
import net from 'net';
import http from 'http';
import dgram from 'dgram';
import assert from 'assert';
import dnspacket from 'dns-packet';
import querystring from 'querystring';
import { dnsQuery, dnsQuerySimple, dnsQueryECH } from './dns-cache.js';
import { lookup6, lookup4, isGoogleIp, isCloudflareIp } from './apnic-table-6.js';

const LOG_DEBUG = console.log;
const LOG_ERROR = console.log;

const dnsObject = {
  type: 'query',
  id: 26858,
  flags: dnspacket.RECURSION_DESIRED,
  questions: [{
    type: 'A',
    name: 'google.com'
  }],
  answers: []
};

const dnsParse = segment => {

  try {
    const msg = dnspacket.decode(segment);

    if (!msg || !msg.questions || !msg.questions.length) {
      return dnsObject;
    }

    if (msg.questions[0].name) {
      return msg;
    }

  } catch (e) {

  }

  return dnsObject;
}

const dnsBuild = message => {
  return dnspacket.encode(message);
}

const options = {
  key: fs.readFileSync('certificate/tls.key'),
  cert: fs.readFileSync('certificate/fullchain.cer'),
  ca: [ fs.readFileSync('certificate/ca.cer') ],
  requestCert: false,
};

function EmptyFunc() {
  console.log("EMPTY CALL");
}

function countof(data) {
  return data.reduce((sum, val) => sum + val.length, 0);
}

function dnsNotify(context) {
  let value = 0;
  let count = 0;
  let fragments = context.buffers;

  for (let i = 0; i < fragments.length; i++) {
    let fragment = fragments[i];

    for (let j = 0; j < fragment.length && count < 2; j++) {
      value = (value << 8) | fragment[j];
      count++;
    }

    let total = countof(fragments);
    LOG_DEBUG(`count ${count} value ${value} total ${total}`);

    if (count == 2 && value + 2 <= countof(fragments)) {
      let fireout = context.resolv;
      context.resolv = v => {};
      fireout();
    }
  }
}

function fetchDnsSegment(context) {
  let okay = false;
  let value = 0;
  let count = 0;
  let fragments = context.buffers;

  for (let i = 0; i < fragments.length; i++) {
    let fragment = fragments[i];

    for (let j = 0; j < fragment.length && count < 2; j++) {
      value = (value << 8) | fragment[j];
      count++;
    }

    let total = countof(fragments);
    LOG_DEBUG(`fetchDnsSegment ${count} value ${value} total ${total}`);

    if (count == 2 && value + 2 <= countof(fragments)) {
      okay = true;
      break;
    }
  }

  if (okay) {
    let sum = 0;
    let ware = [];

    for (let i = 0; i < fragments.length; i++) {
      let fragment = fragments[i];

      ware.push(fragment);
      if (sum + fragment.length >= value + 2) {
	const stream = Buffer.concat(ware);

	if (sum + fragment.length == value + 2) {
	  fragments.splice(0, i + 1);
	} else {
	  fragments[i] = stream.slice(value + 2);
	  fragments.splice(0, i);
	}

	return stream.slice(2, value + 2);
      }

      sum += fragment.length;
    }
  }

  return null;
}

function sendSegment(socket, message) {
  let b = Buffer.alloc(2);
  const segment = dnsBuild(message);

  b.writeUInt16BE(segment.length);

  socket.write(b);
  socket.write(segment);
}

async function prepareDnsSegment(client) {

  const context = {
    resolv: EmptyFunc,
    reject: EmptyFunc,
    buffers: []
  };

  client.on('data', (data) => {
    context.buffers.push(data);
    dnsNotify(context);
  });

  client.on('error', (data) => {
    let fireout = context.reject;
    context.reject = EmptyFunc;
    fireout("error");
  });

  client.on('end', () => {
    let fireout = context.reject;
    context.reject = EmptyFunc;
    LOG_DEBUG('disconnected from server');
    fireout("end");
  });

  try {
    for ( ; ; ) {
      const promise = new Promise((resolv, reject) => {
        context.resolv = resolv;
        context.reject = reject;

        dnsNotify(context);
      });

      LOG_DEBUG("waiting data");

      await promise;

      const oilMessage = fetchDnsSegment(context);
      const dnsMessage = dnsParse(oilMessage);
      const dnsResult  = await dnsQuery(dnsMessage);

      sendSegment(client, dnsResult);
    }
  } catch (e) {
    LOG_DEBUG(`exception ${e}`);
  }

  client.end();
}

const http1 = http.createServer(options, (req, res) => { });
http1.listen(1800);

const tls1 = tls.createServer(options, prepareDnsSegment);
tls1.listen(853,  () => { });

const tcp1 = net.createServer(options, prepareDnsSegment);
tcp1.listen(5300,  () => { });

async function onDnsQuery(segment, rinfo) {
  LOG_DEBUG("UDP SERVER rinfo " + rinfo.address);
  let config = {};

  try {
    const query = dnsParse(segment);
    const result = await dnsQuery(query);
    let out_segment = dnsBuild(result);

    this.send(out_segment, rinfo.port, rinfo.address, (err) => { LOG_ERROR("send error " + err); });
  } catch (e) {
    LOG_ERROR("UDP FAILURE " + e);
  }
}

function onFailure(e) {
  LOG_ERROR(`onFailure ${e}`);
}

const udp6 = dgram.createSocket('udp6');
udp6.on('error', onFailure);
udp6.on('message', onDnsQuery.bind(udp6));
udp6.bind(53, '64:ff9b::127.9.9.9');

function isGoogleDomain(fqdn, answsers) {

    return answsers.some(item => (item.type == "A" || item.type == "AAAA") && isGoogleIp(item.data));
}

async function onDnsQueryEch(segment, rinfo) {
  LOG_DEBUG("UDP SERVER rinfo " + rinfo.address);
  let config = {};

  try {
    let result = null;
    const query = dnsParse(segment);
    const type  = query.questions[0].type;

    switch (type) {
      case 'UNKNOWN_65':
      case 'A':
      case 'AAAA':
        {
          const checker = Object.assign({}, query);
          checker.questions = [Object.assign({}, query.questions[0])];
          checker.questions[0].type = 'A';
          result = await dnsQuerySimple(checker);

          if (isGoogleDomain("", result.answers)) {
            result = await dnsQueryECH(query);
            break;
          }

          checker.questions[0].type = 'AAAA';
          result = await dnsQuerySimple(checker);
          if (isGoogleDomain("", result.answers)) {
            result = await dnsQueryECH(query);
            break;
          }

          result = await dnsQuery(query);
          break;
        }

      default:
        result = await dnsQuerySimple(query);
        break;
    }

    let out_segment = dnsBuild(result);

    this.send(out_segment, rinfo.port, rinfo.address, (err) => { LOG_ERROR("send error " + err); });
  } catch (e) {
    LOG_ERROR("UDP FAILURE " + e);
  }
}
const udpEch = dgram.createSocket('udp4');
udpEch.on('error', onFailure);
udpEch.on('message', onDnsQueryEch.bind(udpEch));
udpEch.bind( {
  address: '127.9.9.9',
  port: 5353,
  exclusive: true,
});

const udp = dgram.createSocket('udp4');
udp.on('error', onFailure);
udp.on('message', onDnsQuery.bind(udp));
udp.bind( {
  address: '127.9.9.9',
  port: 53,
  exclusive: true,
});
