const TcpPortList = [80, 4430];

const NameServers = {
  nearby: { address: "::ffff:192.168.1.1", port: 53},
  // nearby6: { address: "2001:4860:4860::8888", port: 53},
  nearby6: { address: "64:ff9b::8.8.8.8", port: 5300},
  global: { address: "64:ff9b::8.8.8.8", port: 5300},
  // global: { address: "64:ff9b::172.26.0.2", port: 5300},
  global6: { address: "64:ff9b::8.8.8.8", port: 5300},
  // oiling: { address: "::ffff:202.12.30.131", port: 53},
  oiling: { address: "::ffff:203.119.1.1", port: 53},
  // 202.12.30.131 203.119.1.1
};

const Config = {};
Config.oilingMode = "China";
Config.preferNat64 = true;

Config.asiaWrap = false;
Config.dns64ofCloudflare = true;

const PresetRecords = [
  // {name: "ipv4only.arpa", type: "AAAA", data: "2002:1769:c6bd:ffff::"},
  {name: "www.googleapis.cn", type: "AAAA", data: "2607:f8b0:4005:814::2003"},
  {name: "www.googleapis.cn", type: "A", data: "120.253.255.162"},
  {name: "www.google.com", type: "A", data: "142.250.189.164"},
  {name: "stun.parsec.app", type: "A", data: "137.175.53.113"},
  {name: "stun6.parsec.app", type: "AAAA", data: "2001:4860:4864:5:8000::1"},
  // parsecusercontent.com

  // {name: "play.googleapis.com", type: "A", data: "74.125.130.95"},
  // {name: "play.googleapis.com", type: "AAAA", data: "64:ff9b::74.125.130.95"},
  {name: "chatgpt.com", type: "AAAA", data: "64:ff9b::198.23.236.232"},
  {name: "ab.chatgpt.com", type: "AAAA", data: "64:ff9b::198.23.236.232"},
  {name: "www.chatgpt.com", type: "AAAA", data: "64:ff9b::198.23.236.232"},
  {name: "auth.openai.com", type: "AAAA", data: "64:ff9b::198.23.236.232"},
  {name: "chat.openai.com", type: "AAAA", data: "64:ff9b::198.23.236.232"},
  {name: "cdn.oaistatic.com", type: "AAAA", data: "64:ff9b::198.23.236.232"},
  {name: "android.chat.openai.com", type: "AAAA", data: "64:ff9b::198.23.236.232"},

  {name: "mtalk.google.com", type: "A", data: "110.42.145.164"},
  {name: "mtalk.google.com", type: "AAAA", data: "2404:6800:4008:c06::bc"},
  {name: "mtalk.google.com", type: "AAAA", data: "2404:6800:4008:c00::bc"},
  {name: "office.local", type: "AAAA", data: "65:ff9b::172.31.1.30"},

  {name: "time.android.com", type: "A", data: "120.25.115.20"},
  {name: "time.android.com", type: "A", data: "106.55.184.199"},

  {name: "www.gstatic.com", type: "A", data: "203.208.40.2"},
  {name: "gateway.local", type: "A", data: "10.0.13.1"},
  {name: ".local", type: "suffix", data: "deny"},

  {name: "connectivitycheck.gstatic.com", type: "A", data: "203.208.41.98"},
  {name: "connectivitycheck.gstatic.com", type: "AAAA", data: "2401:3800:4002:801::1002"},

  {name: "www.gstatic.com", type: "AAAA", data: "2401:3800:4002:807::1002"},
  {name: "www.gstatic.com", type: "AAAA", data: "2404:6800:4008:c00::bc"},

  {name: ".603030.xyz", type: "suffix", data: "primary" },
  {name: ".cachefiles.net", type: "suffix", data: "primary"},
  {name: "www.googleapis.cn", type: "is", data: "primary"},
  {name: ".wynd.network", type: "suffix", data: "primary"},
  {name: ".aws-wynd.network", type: "suffix", data: "primary"},
  {name: ".amazonaws.com", type: "suffix", data: "primary"},
];

Config.PresetRecords = PresetRecords;

export {TcpPortList, NameServers, Config};
