// Custom percent encoding conforming to Aliyun requirements
function percentEncode(str, spaceAsPlus = false) {
  let out = '';
  const utf8Bytes = new TextEncoder().encode(str);
  for (const byte of utf8Bytes) {
    if (isUnreserved(byte)) {
      out += String.fromCharCode(byte);
    } else if (spaceAsPlus && byte === 0x20) {
      out += '+';
    } else {
      out += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return out;
}

function isUnreserved(byte) {
  return (
    (byte >= 65 && byte <= 90) ||   // A-Z
    (byte >= 97 && byte <= 122) ||  // a-z
    (byte >= 48 && byte <= 57) ||   // 0-9
    byte === 45 ||                  // -
    byte === 95 ||                  // _
    byte === 46 ||                  // .
    byte === 126                    // ~
  );
}

function encodeQuery(values) {
  const keys = Object.keys(values).sort();
  return keys
    .map(key => `${percentEncode(key, true)}=${percentEncode(values[key], true)}`)
    .join('&');
}

function goJsonString(str) {
  let out = '"';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    const code = str.charCodeAt(i);
    switch (ch) {
      case '"': out += '\\"'; break;
      case '\\': out += '\\\\'; break;
      case '\b': out += '\\b'; break;
      case '\f': out += '\\f'; break;
      case '\n': out += '\\n'; break;
      case '\r': out += '\\r'; break;
      case '\t': out += '\\t'; break;
      case '<': out += '\\u003c'; break;
      case '>': out += '\\u003e'; break;
      case '&': out += '\\u0026'; break;
      default:
        if (code <= 0x1f) {
          out += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          out += ch;
        }
    }
  }
  out += '"';
  return out;
}

function goJsonObject(obj) {
  const keys = Object.keys(obj).sort();
  let out = '{';
  for (let i = 0; i < keys.length; i++) {
    if (i > 0) out += ',';
    out += goJsonString(keys[i]) + ':' + goJsonString(obj[keys[i]]);
  }
  out += '}';
  return out;
}

function signatureNonce() {
  const nanos = Date.now() * 1000000;
  const array = new Uint32Array(2);
  crypto.getRandomValues(array);
  const random = (BigInt(array[0]) << 32n) | BigInt(array[1]);
  const randomPositive = random & 0x7fffffffffffffffn;
  return `${nanos}_${randomPositive.toString()}`;
}

async function hmacSha1(key, data) {
  const encoder = new TextEncoder();
  const keyBuf = encoder.encode(key);
  const dataBuf = encoder.encode(data);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBuf,
    { name: "HMAC", hash: { name: "SHA-1" } },
    false,
    ["sign"]
  );

  const signatureBuf = await crypto.subtle.sign("HMAC", cryptoKey, dataBuf);
  return btoa(String.fromCharCode(...new Uint8Array(signatureBuf)));
}

async function aliyunRequest(account, host, version, action, method, extra = {}) {
  const timestamp = new Date().toISOString().substring(0, 19) + 'Z';
  const params = {
    Format: 'JSON',
    Version: version,
    AccessKeyId: account.access_key_id,
    SignatureMethod: 'HMAC-SHA1',
    SignatureVersion: '1.0',
    Action: action,
    Timestamp: timestamp,
    SignatureNonce: signatureNonce(),
    ...extra
  };

  const sortedKeys = Object.keys(params).sort();
  const canonical = sortedKeys
    .map(key => `${percentEncode(key, false)}=${percentEncode(params[key], false)}`)
    .join('&');

  const stringToSign = `${method.toUpperCase()}&${percentEncode('/', false)}&${percentEncode(canonical, false)}`;
  const signatureKey = `${account.access_key_secret}&`;
  const signature = await hmacSha1(signatureKey, stringToSign);

  const url = `https://${host}/?${canonical}&Signature=${percentEncode(signature, false)}`;

  const init = {
    method: method.toUpperCase(),
  };
  if (method.toUpperCase() === 'POST') {
    init.headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    };
    init.body = '';
  }

  const response = await fetch(url, init);
  const text = await response.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error(`HTTP ${response.status} (invalid JSON): ${text.substring(0, 200)}`);
  }

  if (data.Code && data.Code !== '') {
    throw new Error(`API [${data.Code}]: ${data.Message}`);
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${data.Message || text}`);
  }

  return data;
}

async function sendWebhook(webhook, message, logger) {
  if (!webhook.enabled || !webhook.url.startsWith("generic://")) {
    return;
  }

  try {
    const parsedUrlStr = webhook.url.replace("generic://", "https://");
    const parsedUrl = new URL(parsedUrlStr);

    const headers = {};
    const payload = {};
    const forwarded = {};
    let contentType = "application/json";
    let messageKey = "message";
    let requestMethod = "POST";

    const seen = new Set();
    for (const [key, value] of parsedUrl.searchParams.entries()) {
      if (seen.has(key)) continue;
      seen.add(key);

      if (key.startsWith('@')) {
        const headerName = key.slice(1);
        headers[headerName] = value;
      } else if (key.startsWith('$')) {
        const payloadKey = key.slice(1);
        payload[payloadKey] = value;
      } else if (key.startsWith('_')) {
        const forwardedKey = key.slice(1);
        forwarded[forwardedKey] = value;
      } else {
        const lowerKey = key.toLowerCase();
        if (lowerKey === 'contenttype') {
          contentType = value;
        } else if (lowerKey === 'messagekey') {
          messageKey = value;
        } else if (lowerKey === 'requestmethod') {
          requestMethod = value.toUpperCase();
        } else {
          forwarded[key] = value;
        }
      }
    }

    payload[messageKey] = message;
    const body = goJsonObject(payload);

    const finalUrl = new URL(parsedUrl.origin + parsedUrl.pathname);
    const rawQuery = encodeQuery(forwarded);
    if (rawQuery) {
      finalUrl.search = rawQuery;
    }

    headers['Content-Type'] = contentType;

    const response = await fetch(finalUrl.toString(), {
      method: requestMethod,
      headers: headers,
      body: body
    });

    if (!response.ok) {
      const text = await response.text();
      logger.log(`webhook: HTTP ${response.status}: ${text}`);
    }
  } catch (err) {
    logger.log(`webhook error: ${err.message}`);
  }
}

class Logger {
  logs = [];

  log(message) {
    const now = new Date();
    const pad = (n) => n.toString().padStart(2, '0');
    const timestamp = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())} ${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())} UTC`;
    const line = `${timestamp} ${message}`;
    console.log(line);
    this.logs.push(line);
  }

  getLogs() {
    return this.logs.join("\n");
  }
}

function parseConfig(env) {
  if (!env.CONFIG) {
    throw new Error("Missing CONFIG environment variable");
  }

  let config;
  if (typeof env.CONFIG === 'object' && env.CONFIG !== null) {
    config = env.CONFIG;
  } else {
    try {
      config = JSON.parse(env.CONFIG);
    } catch (err) {
      throw new Error(`Failed to parse CONFIG JSON: ${err.message}`);
    }
  }

  config.accounts = config.accounts || [];
  config.webhook = config.webhook || { enabled: false, url: "" };
  return config;
}

async function processAccount(account, webhook, logger) {
  const quotaGb = 200.0;
  let trafficGb = 0;
  let status = "Unknown";
  let actionTaken = "None";

  try {
    if (!account.access_key_id || !account.access_key_secret || !account.region_id || !account.instance_id) {
      throw new Error("Missing required account configuration parameters");
    }

    // 1. Get traffic
    try {
      const data = await aliyunRequest(
        account,
        "cdt.aliyuncs.com",
        "2021-08-13",
        "ListCdtInternetTraffic",
        "POST"
      );
      const trafficDetails = data.TrafficDetails || [];
      let totalTraffic = 0;
      for (const detail of trafficDetails) {
        totalTraffic += detail.Traffic || 0;
      }
      trafficGb = totalTraffic / (1024.0 * 1024.0 * 1024.0);
    } catch (err) {
      throw new Error(`get traffic: ${err.message}`);
    }

    // 2. Get instance status
    try {
      const data = await aliyunRequest(
        account,
        `ecs.${account.region_id}.aliyuncs.com`,
        "2014-05-26",
        "DescribeInstanceStatus",
        "GET",
        {
          RegionId: account.region_id,
          InstanceId: account.instance_id
        }
      );
      status = data.InstanceStatuses?.InstanceStatus?.[0]?.Status;
      if (!status) {
        throw new Error("no status returned");
      }
    } catch (err) {
      throw new Error(`get status: ${err.message}`);
    }

    const stats = `${trafficGb.toFixed(2)} / ${quotaGb.toFixed(0)} GB (${(trafficGb / quotaGb * 100.0).toFixed(1)}%)`;

    // 3. Control instance status if threshold crossed
    if (status === "Stopped" && trafficGb < account.threshold_gb) {
      try {
        await aliyunRequest(
          account,
          `ecs.${account.region_id}.aliyuncs.com`,
          "2014-05-26",
          "StartInstance",
          "GET",
          {
            RegionId: account.region_id,
            InstanceId: account.instance_id
          }
        );
        actionTaken = "Started";
        const msg = `🟢 Starting | ${stats}`;
        logger.log(`[${account.instance_id}] ${msg}`);
        await sendWebhook(webhook, `[${account.instance_id}] ${msg}`, logger);
        status = "Running";
      } catch (err) {
        throw new Error(`start: ${err.message}`);
      }
    } else if (status === "Running" && trafficGb >= account.threshold_gb) {
      try {
        await aliyunRequest(
          account,
          `ecs.${account.region_id}.aliyuncs.com`,
          "2014-05-26",
          "StopInstance",
          "GET",
          {
            RegionId: account.region_id,
            InstanceId: account.instance_id,
            StoppedMode: account.shutdown_mode
          }
        );
        actionTaken = "Stopped";
        const msg = `🛑 Stopping | ${stats}`;
        logger.log(`[${account.instance_id}] ${msg}`);
        await sendWebhook(webhook, `[${account.instance_id}] ${msg}`, logger);
        status = "Stopped";
      } catch (err) {
        throw new Error(`stop: ${err.message}`);
      }
    } else if (status === "Running") {
      logger.log(`[${account.instance_id}] ✅ Running | ${stats}`);
    } else {
      logger.log(`[${account.instance_id}] ⏸️ Stopped | ${stats}`);
    }

    return {
      instanceId: account.instance_id,
      regionId: account.region_id,
      status,
      trafficGb,
      thresholdGb: account.threshold_gb,
      shutdownMode: account.shutdown_mode,
      actionTaken
    };

  } catch (err) {
    logger.log(`[${account.instance_id}] ⚠️ Error: ${err.message}`);
    return {
      instanceId: account.instance_id,
      regionId: account.region_id,
      status,
      trafficGb,
      thresholdGb: account.threshold_gb,
      shutdownMode: account.shutdown_mode,
      actionTaken,
      error: err.message
    };
  }
}

async function runMonitor(env, logger) {
  const config = parseConfig(env);
  const results = [];

  for (const account of config.accounts) {
    const res = await processAccount(account, config.webhook, logger);
    results.push(res);
  }

  return results;
}

export default {
  async fetch(request, env, ctx) {
    const logger = new Logger();

    try {
      await runMonitor(env, logger);
    } catch (err) {
      logger.log(`⚠️ Critical Error: ${err.message}`);
    }
    const logs = logger.getLogs();

    return new Response(logs, {
      headers: { "Content-Type": "text/plain; charset=utf-8" }
    });
  },

  async scheduled(event, env, ctx) {
    const logger = new Logger();
    ctx.waitUntil((async () => {
      try {
        await runMonitor(env, logger);
      } catch (err) {
        logger.log(`⚠️ Scheduled task critical error: ${err.message}`);
      }
    })());
  }
};
