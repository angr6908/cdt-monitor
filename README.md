# cdt-monitor
## Webhook Notifications
Please refer to the [Shoutrrr documentation](https://containrrr.dev/shoutrrr/v0.8/services/generic/).
## Log Serving with Caddy
### Caddyfile
```
example.com {
	templates
	header Content-Type "text/html; charset=utf-8"
	respond `<meta name="viewport" content="width=device-width"><style>:root{color-scheme:light dark}body{font:18px monospace;white-space:pre-wrap}</style>{{readFile "cdt-monitor.log"}}`
}
```
### compose.yml
```
services:
  caddy:
    image: caddy:latest
    container_name: caddy
    network_mode: host
    restart: always
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - /path/to/cdt-monitor/cdt-monitor.log:/srv/cdt-monitor.log:ro
```
