import dgram from 'dgram';
import dnspacket from 'dns-packet';

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

const FAR_PORT = 53;
const FAR_SERVER = "::ffff:223.5.5.5";

function dnsQuery(message) {

  const cb = (resolv, reject) => {
    let timer = null;
    let timerReject = setTimeout(reject, 3000);

    const on_message = (data, rinfo) => {
      LOG_DEBUG("rinfo " + rinfo.address + " fast " + data.length);
      const result = dnsParse(data);
      const fire = (result == dnsObject? reject: resolv);

      clearTimeout(timerReject);
      clearTimeout(timer);
      fire(result);
    };

    const udp6 = dgram.createSocket('udp6');

    udp6.on("message", on_message);
    const oil_msg = dnsBuild(message);
    const cb = i => udp6.send(oil_msg, FAR_PORT, FAR_SERVER, LOG_DEBUG);

    timer = setTimeout(cb, 5000);
    cb();
  };

  return new Promise(cb);
}

export { dnsQuery };
