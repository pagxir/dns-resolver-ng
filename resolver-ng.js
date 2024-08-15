import fs from 'fs';
import tls from 'tls';
import net from 'net';
import http from 'http';
import dgram from 'dgram';
import assert from 'assert';
import dnspacket from 'dns-packet';
import querystring from 'querystring';

const nsDecode = segment => {

  try {
    const msg = dnspacket.decode(segment);

    if (!msg || !msg.questions || !msg.questions.length) {
      return null;
    }

    if (msg.questions[0].name) {
      return msg;
    }

  } catch (e) {

  }

  return null;
}

const options = {
  key: fs.readFileSync('certificate/tls.key'),
  cert: fs.readFileSync('certificate/fullchain.cer'),
  ca: [ fs.readFileSync('certificate/ca.cer') ],
  requestCert: false,
};

function EMPTY() {
  console.log("EMPTY CALL");
}

const LOG_DEBUG = console.log;

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

function sendSegment(socket, segment) {
  let b = Buffer.alloc(2);
  b.writeUInt16BE(segment.length);

  socket.write(b);
  socket.write(segment);
}

async function prepareDnsSegment(client) {

  const context = {
    resolv: EMPTY,
    reject: EMPTY,
    buffers: []
  };

  client.on('data', (data) => {
    context.buffers.push(data);
    dnsNotify(context);
  });

  client.on('end', () => {
    let fireout = context.reject;
    context.reject = EMPTY;
    LOG_DEBUG('disconnected from server');
    fireout();
  });

  const FAR_PORT = 53;
  const FAR_SERVER = "::ffff:223.5.5.5";

  const udp6 = dgram.createSocket('udp6');

  const promise = new Promise((resolv, reject) => {
    context.resolv = resolv;
    context.reject = reject;
    
    dnsNotify(context);
  });

  LOG_DEBUG("waiting data");

  await promise;

  const oil_msg = fetchDnsSegment(context);
  const on_message = (data, rinfo) => {
      LOG_DEBUG("rinfo " + rinfo.address + " fast " + data.length);
      sendSegment(client, data);
  };

  udp6.on("message", on_message);
  udp6.send(oil_msg, FAR_PORT, FAR_SERVER, LOG_DEBUG);
}

const http1 = http.createServer(options, (req, res) => { });
http1.listen(1800);

const tls1 = tls.createServer(options, prepareDnsSegment);
tls1.listen(8530,  () => { });

const tcp1 = net.createServer(options, prepareDnsSegment);
tcp1.listen(5300,  () => { });

function onDnsQuery6(segment, rinfo) { }
function onDnsQuery4(segment, rinfo) { }
function onFailure(e) { }

const udp6 = dgram.createSocket('udp6');
udp6.on('error', onFailure);
udp6.on('message', onDnsQuery6);
udp6.bind(53, '64:ff9b::1');

const udp = dgram.createSocket('udp4');
udp.on('error', onFailure);
udp.on('message', onDnsQuery4);
udp.bind( {
  address: '127.9.9.9',
  port: 53,
  exclusive: true,
});
