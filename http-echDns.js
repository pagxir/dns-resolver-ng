import fs from 'fs';
import http from 'http';
import dgram from 'dgram';
import assert from 'assert';
import querystring from 'querystring';
import { dnsParse, dnsBuild } from './dns-utils.js';
import { LOG_ERROR, LOG_DEBUG } from './dns-utils.js';
import { dnsQuery, dnsQuerySimple, dnsQueryECH } from './dns-cache.js';
import { isGoogleIp, isCloudflareIp } from './apnic-table-6.js';

function isGoogleDomain(fqdn, answsers) {
    // return false;
    if (fqdn.endsWith("v2ex.com")) return true;
    return answsers.some(item => (item.type == "A" || item.type == "AAAA") && isGoogleIp(item.data));
}

function isCloudflareDomain(fqdn, answsers) {
    // return false;
    if (fqdn.endsWith("v2ex.com")) return true;
    return answsers.some(item => (item.type == "A" || item.type == "AAAA") && isCloudflareIp(item.data));
}

async function httpEchQuery(fragment, enableEch, enableDns64) {
  let result = null;
  const query = dnsParse(fragment);
  const type  = query.questions[0].type;

  switch (type) {
    case 'UNKNOWN_65':
    case 'A':
    case 'AAAA':
      const checker = Object.assign({}, query);
      checker.questions = [Object.assign({}, query.questions[0])];
      checker.questions[0].type = 'A';
      result = await dnsQuerySimple(checker, false);

      if (!enableEch) {

	let isCloudflare = isCloudflareDomain(checker.questions[0].name, result.answers);
	if (!isCloudflare) {
	  checker.questions[0].type = 'AAAA';
	  result = await dnsQuerySimple(checker, false);
	  isCloudflare = isCloudflareDomain(checker.questions[0].name, result.answers);
	}

	if (!isCloudflare) {
          LOG_DEBUG("no cloudflare name=" + checker.questions[0].name);
	  result = await dnsQuerySimple(query, enableDns64);
	  break;
	}

	result  = Object.assign({}, query);
	result.type = "response";

	let data = [];
	switch (result.questions[0].type) {
	  case 'AAAA':
	    data.push({name: result.questions[0].name, type: 'AAAA', ttl: 3600, data: "64:ff9b::198.23.236.232"});
	    break;

	  case 'A':
	    data.push({name: result.questions[0].name, type: 'A', ttl: 3600, data: "198.23.236.232"});
	    break;

	  default:
	    break;
	}
        LOG_DEBUG("YES cloudflare name=" + checker.questions[0].name);
	result.answers = data;
	break;
      }

      if (isGoogleDomain(checker.questions[0].name, result.answers)) {
	result = await dnsQueryECH(query);
	break;
      }

      checker.questions[0].type = 'AAAA';
      result = await dnsQuerySimple(checker, false);
      if (isGoogleDomain(checker.questions[0].name, result.answers)) {
	result = await dnsQueryECH(query);
	break;
      }

      result = await dnsQuerySimple(query, enableDns64);
      break;

    default:
      result = await dnsQuery(query);
      break;
  }

  return dnsBuild(result);
}

async function processHttpDns(req, res) {
  const path = req.url;
  LOG_DEBUG("path=" + path);

  var dns_cb = b => {
    res.statusCode = 200;

    res.setHeader("Server", "cloudflare");
    res.setHeader("Date", new Date());
    res.setHeader("Content-Type", "application/dns-message");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Length", b.length);

    res.end(b);
  };

  const DOHPathPrefix = ["/ech-query", "/dns64-query", "/dns-query", "/ech64-query"];
  const useDOH = DOHPathPrefix.some(item => path.startsWith(item));
  const useECH = path.startsWith("/ech-query") || path.startsWith("/ech64-query");
  const useDNS64 = path.startsWith("/dns64-query") || path.startsWith("/dns64-query");

  if (useDOH && req.method === "GET") {
    if (path.includes("?")) {
      try {
	const pairs = querystring.parse(path.split("?")[1]);
	const fragment = Buffer.from(pairs.dns, 'base64');

	LOG_DEBUG("query finish");
        const out_segment = await httpEchQuery(fragment, useECH, useDNS64);
	dns_cb(out_segment);
	return;
      } catch (e) {
	LOG_DEBUG("query failure" + e);
      }
    }

    res.statusCode = 403;

    res.setHeader("Server", "cloudflare");
    res.setHeader("Date", new Date());
    res.setHeader("Content-Type", "application/dns-message");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Length", 0);

    res.end();
    return;
  }

  if (useDOH && req.method === "POST") {

    try {
      const buffers = [];
      for await (const data of req)
	buffers.push(data);

      const fragment = Buffer.concat(buffers);
      const out_segment = await httpEchQuery(fragment, useECH, useDNS64);
      dns_cb(out_segment);
    } catch (e) {
      res.statusCode = 403;

      res.setHeader("Server", "cloudflare");
      res.setHeader("Date", new Date());
      res.setHeader("Content-Type", "application/dns-message");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Content-Length", 0);

      res.end();
    }
    return;
  }

  if (path.startsWith("/notatall/")) {
    try {
      let mimeType = "application/octet-stream";
      if (path.endsWith(".html") || path.endsWith(".htm")) {
        mimeType = "text/html";
      } else if (path.endsWith(".png")) {
        mimeType = "image/png";
      } else if (path.endsWith("yaml")) {
        mimeType = "text/yaml";
      }

      let stat = fs.statSync("./" + path);
      if (!stat.isDirectory()) {
        let rs = fs.createReadStream("./" + path, {
          highWaterMark: 65536
        })
        res.setHeader("Content-Type", mimeType);
        res.setHeader("Content-Length", stat.size);
        res.statusCode = 200;
        rs.pipe(res);
      }
    } catch(e) {
      LOG_ERROR('XError:', e.stack);
      res.end();
    }
    return;
  }

  if (path.startsWith("/proxy_config/")) {
    try {
      // var PROXY_COMMAND = "SOCKS 127.0.0.1:8888";
      var PROXY_COMMAND = "SOCKS 103.45.162.65:18881";
      var args = path.split("/");
      args.find(item => { if(item.startsWith("SOCKS")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
      args.find(item => { if(item.startsWith("PROXY")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
      args.find(item => { if(item.startsWith("HTTPS")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
      args.find(item => { if(item.startsWith("HTTP")) { PROXY_COMMAND=item.replace("@", " "); return true; } });
      var data = fs.readFileSync("proxy.pac", 'utf8').replace("PROXY 127.0.0.1:8080", PROXY_COMMAND);
      var mimeType = "text/javascript";
      res.setHeader("Content-Type", mimeType);
      res.statusCode = 200;
      res.end(data); 
    } catch(e) {
      LOG_ERROR('XError:', e.stack);
      res.end();
    }
    return;
  }

  {
    let b = "<html/>"
    res.statusCode = 200;
    if (path.startsWith("/generate_204")) {
      res.statusCode = 204;
      b = "";
    }

    res.setHeader("Server", "cloudflare");
    res.setHeader("Date", new Date());
    res.setHeader("Content-Type", "text/html");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Length", b.length);

    res.end(b);
  }
}

export {httpEchQuery, processHttpDns};
