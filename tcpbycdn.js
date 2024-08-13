import { TcpPortList } from './config.js';
import { isCloudflareIp }  from './apnic-table-6.js';

const LOG_DEBUG = console.log;

async function onAccept(socket) {
  const remoteAddress = socket.remoteAddress;
  socket.on("error", e => LOG_DEBUG("tcp error " + e));
  socket.on("close", e => socket.end());

  const target = socket.address();
  const address = "" + target.address;

  LOG_DEBUG("FROM " + remoteAddress);
  LOG_DEBUG("TEST " + address);

  let TWO = "one.cachefiles.net";
  let PORT = 40403;

  if (address.startsWith("64:ff9b::")) {
    const args = address.split(":");
    if (args && args.length > 2) {
      const left = parseInt(args[args.length -2], 16);
      const right = parseInt(args[args.length -1], 16);

      TWO = (left >> 8) + '.' + (left % 256) + '.' + (right >> 8) + '.' + (right % 256);
      PORT = (target.port > 8000? target.port - 8000: target.port);
      LOG_DEBUG("destination: " + TWO);
    }
  } else if (address.startsWith("::ffff:")) {
    const args = address.split(":");
    if (args && args.length > 2) {
      TWO = args[args.length -1];

      PORT = (target.port > 8000? target.port - 8000: target.port);
      LOG_DEBUG("destination: " + TWO);
    }
  }

  if (table.isCloudflareIp(TWO)) {
    TWO = "one.cachefiles.net";
    PORT = 40403;
  }

  const url = "wss://speedup.603030.xyz/tcp/" + TWO + "/" + PORT;
  LOG_DEBUG("URL: " + url);
  const ws = new WebSocket(url);

  const duplex = WebSocket.createWebSocketStream(ws, { });
  duplex.on('error', console.error);
  ws.timer = setInterval(v => ws.ping(), 5000);

  try {
    await Promise.all([socket.pipe(duplex), duplex.pipe(socket)]);
  } catch (e) {
    LOG_DEBUG("e = " + e);
  } finally {
    clearInterval(ws.timer);
  }

  // duplex.pipe(process.stdout);
  // process.stdin.pipe(duplex);
};

const log = err => LOG_DEBUG(`server bound ${err}`);
const callback = port => net.createServer(options, onAccept).listen(port, log);

TcpPortList.forEach(callback);
