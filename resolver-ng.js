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

const http1 = http.createServer(options, (req, res) => { });
http1.listen(1800);

const tls1 = tls.createServer(options, (socket) => { });
tls1.listen(8530,  () => { });

const tcp1 = net.createServer(options, (socket) => { });
tcp1.listen(5300,  () => { });

function onDnsQuery6(segment, rinfo) { }
function onDnsQuery4(segment, rinfo) { }
function onFailure(e) { }

const udp6 = dgram.createSocket('udp6');
udp6.on('error', onFailure);
udp6.on('message', onDnsQuery6);
udp6.bind(53, '64:ff9b::1');

const udp= dgram.createSocket('udp4');
udp.on('error', onFailure);
udp.on('message', onDnsQuery4);
udp.bind( {
  address: '127.9.9.9',
  port: 53,
  exclusive: true,
});
