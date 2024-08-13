const TcpPortList = [];

const OuterNameServer = {
  address: "::ffff:223.5.5.5",
  port: 53,
  wrap: false
};

const InnerNameServer = {
  address: "::ffff:192.168.1.1",
  port: 53,
  wrap: false
};

const FinalNameServer = {
  address: "::ffff:8.8.8.8",
  port: 53,
  wrap: false
};

const INVALID_PRECEDENCE  = 100;
const FAILURE_PRECEDENCE  = 99;

const IPV4_INNER_PRECEDENCE = 1;
const IPV4_OUTER_PRECEDENCE = 3;

const IPV6_INNER_PRECEDENCE = 2;
const IPV6_OUTER_PRECEDENCE = 90;

const NAT64_INNER_PRECEDENCE = 8;
const NAT64_OUTER_PRECEDENCE = 3;

const PresetRecords = [
  // {name: "ipv4only.arpa", type: "AAAA", data: "2002:1769:c6bd:ffff::"},
  {name: "www.googleapis.cn", type: "AAAA", data: "2607:f8b0:4005:814::2003"},
  {name: "www.googleapis.cn", type: "A", data: "120.253.255.162"},
  // {name: "www.google.com", type: "A", data: "8.8.8.80"}

  // {name: "play.googleapis.com", type: "A", data: "74.125.130.95"},
  // {name: "play.googleapis.com", type: "AAAA", data: "64:ff9b::74.125.130.95"},

  {name: "mtalk.google.com", type: "A", data: "110.42.145.164"},
  {name: "mtalk.google.com", type: "AAAA", data: "2404:6800:4008:c06::bc"},
  {name: "mtalk.google.com", type: "AAAA", data: "2404:6800:4008:c00::bc"},
  {name: "office.local", type: "AAAA", data: "65:ff9b::172.31.1.30"},

  {name: "time.android.com", type: "A", data: "120.25.115.20"},
  {name: "time.android.com", type: "A", data: "106.55.184.199"},

  {name: "www.gstatic.com", type: "A", data: "203.208.40.2"},
  {name: "gateway.local", type: "A", data: "10.0.3.1"},

  {name: "connectivitycheck.gstatic.com", type: "A", data: "203.208.41.98"},
  {name: "connectivitycheck.gstatic.com", type: "AAAA", data: "2401:3800:4002:801::1002"},

  {name: "www.gstatic.com", type: "AAAA", data: "2401:3800:4002:807::1002"},
  {name: "www.gstatic.com", type: "AAAA", data: "2404:6800:4008:c00::bc"},
];

export {TcpPortList, OuterNameServer, InnerNameServer, FinalNameServer, PresetRecords};
export {INVALID_PRECEDENCE, FAILURE_PRECEDENCE, NAT64_OUTER_PRECEDENCE, NAT64_INNER_PRECEDENCE};
export {IPV4_INNER_PRECEDENCE, IPV4_OUTER_PRECEDENCE, IPV6_INNER_PRECEDENCE, IPV6_OUTER_PRECEDENCE};
