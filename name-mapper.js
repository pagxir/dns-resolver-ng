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

  if (data.questions && data.questions[0].name) {
    data.questions[0].name = data.questions[0].name.toLowerCase();
  }

  return data;
}

const resolver_copy = {
  Q: msg => msg,
  R: msg => msg,
};

function reverse(str)
{
  return str.split("").reverse().join("");
}

function leftShift(str)
{
  let suffixes = str.substring(1);
  return suffixes + str.charAt(0);
}

function rightShift(str)
{
  let suffixes = str.substring(0, str.length - 1);
  return str.charAt(str.length -1) + suffixes;
}

const DOMAINS = ["net", "com", "org", "co", "edu", "gov"];

function domainRewrap(host) {
  let parts = host.split(".");
  let last = parts.length;
  let cc = 0;

  if (last > 0 && parts[last - 1].length == 2) {
    cc = 1;
    last--;
  }

  if (last > 0 && (cc == 0 || DOMAINS.includes(parts[last -1]))) {
    last--;
    parts[last] = reverse(parts[last]);
  }

  if (last > 0) {
    last--;
    parts[last] = leftShift(parts[last]);
  }

  return parts.join(".");
}

function domainUnwrap(host) {
  let parts = host.split(".");
  let last = parts.length;
  let cc = 0;

  if (last > 0 && parts[last - 1].length == 2) {
    cc = 1;
    last--;
  }

  if (last > 0 && (cc == 0 || DOMAINS.includes(reverse(parts[last -1])))) {
    last--;
    parts[last] = reverse(parts[last]);
  }

  if (last > 0) {
    last--;
    parts[last] = rightShift(parts[last]);
  }

  return parts.join(".");
}

const name_encode = name => {
  return domainRewrap(name) + ".cootail.com";
};

const name_decode = name => {
  return domainUnwrap(name.substring(0, name.length - 12));
};

const QUERY_DOMAIN_JSON = {
  type: 'query',
  id: 26858,
  flags: dnsp.RECURSION_DESIRED,
  questions: [{
    type: 'A',
    name: 'google.com'
  }]
};

const resolver_coder = {
  Q: msg => {
    let q = JSON.parse(JSON.stringify(QUERY_DOMAIN_JSON));
    q.questions[0].name = name_encode(msg.questions[0].name);
    q.questions[0].type = msg.questions[0].type;
    q.additionals = msg.additionals;
    q.id = msg.id;
    return q;
  },

  R: msg => {
    const name_origin = msg.questions[0].name;
    const name_decoded = name_decode(name_origin);

    msg.questions[0].name = name_decoded;
    msg.answers.map(item => { return item.name == name_origin && (item.name = name_decoded); });
    return msg;
  },
};

const CATEGORIES = ["www.v2ex.com", "cdn.v2ex.com", "www.quora.com", "auth0.openai.com", "tcr9i.openai.com", "tcr9i.chat.openai.com", "cdn.oaistatic.com", "cdn.auth0.com", "cdn.openai.com", "api.openai.com", "platform.openai.com", "gist.github.com", "chat.openai.com", "jp.v2ex.com"]
