# cdt-monitor (Cloudflare Workers)

Monitors Aliyun CDT traffic and starts/stops an ECS instance when a traffic threshold is crossed, with optional webhook notifications.

## Setup

1. In the Cloudflare dashboard, go to **Workers & Pages → Create → Start with Hello World!**, deploy it, then **Edit code** and replace the contents with [`worker.js`](worker.js).
2. Add a **Cron Trigger** (Settings → Triggers), e.g. `* * * * *` to run every minute.
3. Add a secret named **`CONFIG`** (Settings → Variables) containing your configuration as a JSON string:

```json
{
  "accounts": [
    {
      "access_key_id": "YOUR_ACCESS_KEY_ID",
      "access_key_secret": "YOUR_ACCESS_KEY_SECRET",
      "region_id": "cn-hongkong",
      "instance_id": "i-bp1xxxxxxxxx",
      "threshold_gb": 150,
      "shutdown_mode": "StopCharging"
    }
  ],
  "webhook": {
    "enabled": true,
    "url": "generic://webhook.example.com/notify?@Authorization=Bearer%20YOUR_WEBHOOK_TOKEN&@X-Source=cdt-monitor&$service=cdt-monitor&$severity=warning&_route=ops-alerts&_token=YOUR_FORWARD_TOKEN&contenttype=application%2Fjson&messagekey=text&requestmethod=POST"
  }
}
```

Visiting the worker's URL runs a check immediately and returns the log output.
