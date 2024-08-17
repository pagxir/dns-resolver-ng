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

export {dnsObject, LOG_ERROR, LOG_DEBUG, dnsBuild, dnsParse};
