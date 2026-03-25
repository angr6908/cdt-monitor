package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	quotaGB        = 200.0
	logRetainLines = 1000
)

type Config struct {
	Accounts []Account `json:"accounts"`
	Webhook  Webhook   `json:"webhook"`
}

type Account struct {
	AccessKeyId     string  `json:"access_key_id"`
	AccessKeySecret string  `json:"access_key_secret"`
	RegionId        string  `json:"region_id"`
	InstanceId      string  `json:"instance_id"`
	ThresholdGB     float64 `json:"threshold_gb"`
	ShutdownMode    string  `json:"shutdown_mode"`
}

type Webhook struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

var (
	httpClient    = &http.Client{Timeout: 15 * time.Second}
	webhookClient = &http.Client{Timeout: 10 * time.Second}
)

type prependWriter struct{ path string }

func (w prependWriter) Write(p []byte) (int, error) {
	old, _ := os.ReadFile(w.path)
	content := strings.TrimRight(string(p), "\n") + "\n" + string(old)
	if lines := strings.SplitN(content, "\n", logRetainLines+2); len(lines) > logRetainLines+1 {
		content = strings.Join(lines[:logRetainLines], "\n") + "\n"
	}
	os.WriteFile(w.path, []byte(content), 0644)
	return len(p), nil
}

func (acc Account) ecsHost() string { return "ecs." + acc.RegionId + ".aliyuncs.com" }

func (acc Account) request(host, version, action, method string, extra map[string]string) ([]byte, error) {
	params := map[string]string{
		"Format": "JSON", "Version": version, "AccessKeyId": acc.AccessKeyId,
		"SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "Action": action,
		"Timestamp":      time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureNonce": fmt.Sprintf("%d_%d", time.Now().UnixNano(), rand.Int63()),
	}
	for k, v := range extra {
		params[k] = v
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, pEncode(k)+"="+pEncode(params[k]))
	}
	canonical := strings.Join(parts, "&")

	mac := hmac.New(sha1.New, []byte(acc.AccessKeySecret+"&"))
	mac.Write([]byte(strings.ToUpper(method) + "&" + pEncode("/") + "&" + pEncode(canonical)))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(strings.ToUpper(method),
		fmt.Sprintf("https://%s/?%s&Signature=%s", host, canonical, pEncode(sig)),
		bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(method, "POST") {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, action, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var apiErr struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Code != "" {
		return nil, fmt.Errorf("API [%s]: %s", apiErr.Code, apiErr.Message)
	}
	return body, nil
}

func (acc Account) trafficGB() (float64, error) {
	body, err := acc.request("cdt.aliyuncs.com", "2021-08-13", "ListCdtInternetTraffic", "POST", nil)
	if err != nil {
		return 0, err
	}
	var res struct {
		TrafficDetails []struct {
			Traffic float64 `json:"Traffic"`
		} `json:"TrafficDetails"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return 0, err
	}
	var total float64
	for _, d := range res.TrafficDetails {
		total += d.Traffic
	}
	return total / (1024 * 1024 * 1024), nil
}

func (acc Account) status() (string, error) {
	body, err := acc.request(acc.ecsHost(), "2014-05-26", "DescribeInstanceStatus", "GET",
		map[string]string{"RegionId": acc.RegionId, "InstanceId": acc.InstanceId})
	if err != nil {
		return "", err
	}
	var res struct {
		InstanceStatuses struct {
			InstanceStatus []struct {
				Status string `json:"Status"`
			} `json:"InstanceStatus"`
		} `json:"InstanceStatuses"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	if len(res.InstanceStatuses.InstanceStatus) == 0 {
		return "", fmt.Errorf("no status returned for %s", acc.InstanceId)
	}
	return res.InstanceStatuses.InstanceStatus[0].Status, nil
}

func (acc Account) control(stop bool) error {
	action, params := "StartInstance", map[string]string{"RegionId": acc.RegionId, "InstanceId": acc.InstanceId}
	if stop {
		action, params["StoppedMode"] = "StopInstance", acc.ShutdownMode
	}
	_, err := acc.request(acc.ecsHost(), "2014-05-26", action, "GET", params)
	return err
}

func (acc Account) process(wh Webhook) error {
	traffic, err := acc.trafficGB()
	if err != nil {
		return fmt.Errorf("get traffic: %w", err)
	}
	status, err := acc.status()
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	stats := fmt.Sprintf("%.2f / %.0f GB (%.1f%%)", traffic, quotaGB, traffic/quotaGB*100)

	switch {
	case status == "Stopped" && traffic < acc.ThresholdGB:
		if err := acc.control(false); err != nil {
			return fmt.Errorf("start: %w", err)
		}
		logNotify(wh, "🟢 Starting | "+stats)
	case status == "Running" && traffic >= acc.ThresholdGB:
		if err := acc.control(true); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		logNotify(wh, "🛑 Stopping | "+stats)
	case status == "Running":
		log.Printf("✅ Running | %s", stats)
	default:
		log.Printf("⏸️ Stopped | %s", stats)
	}
	return nil
}

func logNotify(wh Webhook, msg string) {
	log.Print(msg)
	sendWebhook(wh, msg)
}

func sendWebhook(wh Webhook, message string) {
	if !wh.Enabled || !strings.HasPrefix(wh.URL, "generic://") {
		return
	}
	parsed, err := url.Parse(strings.Replace(wh.URL, "generic://", "https://", 1))
	if err != nil {
		log.Printf("webhook: invalid URL: %v", err)
		return
	}

	headers, payload, forwarded := make(http.Header), make(map[string]interface{}), url.Values{}
	contentType, messageKey, reqMethod := "application/json", "message", "POST"

	for key, values := range parsed.Query() {
		val := values[0]
		switch {
		case strings.HasPrefix(key, "@"):
			headers.Set(strings.TrimPrefix(key, "@"), val)
		case strings.HasPrefix(key, "$"):
			payload[strings.TrimPrefix(key, "$")] = val
		case strings.HasPrefix(key, "_"):
			forwarded.Set(strings.TrimPrefix(key, "_"), val)
		default:
			switch strings.ToLower(key) {
			case "contenttype":
				contentType = val
			case "messagekey":
				messageKey = val
			case "requestmethod":
				reqMethod = strings.ToUpper(val)
			default:
				forwarded.Set(key, val)
			}
		}
	}

	payload[messageKey] = message
	body, _ := json.Marshal(payload)
	parsed.RawQuery = forwarded.Encode()

	req, err := http.NewRequest(reqMethod, parsed.String(), bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook: %v", err)
		return
	}
	req.Header = headers
	req.Header.Set("Content-Type", contentType)

	resp, err := webhookClient.Do(req)
	if err != nil {
		log.Printf("webhook: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func pEncode(s string) string {
	r := url.QueryEscape(s)
	r = strings.ReplaceAll(r, "+", "%20")
	r = strings.ReplaceAll(r, "*", "%2A")
	r = strings.ReplaceAll(r, "%7E", "~")
	return r
}

func main() {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(io.MultiWriter(os.Stderr, prependWriter{filepath.Join(dir, "cdt-monitor.log")}))

	cfgPath := flag.String("c", filepath.Join(dir, "conf.json"), "config file path")
	flag.Parse()

	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	for i, acc := range cfg.Accounts {
		if acc.AccessKeyId == "" || acc.AccessKeySecret == "" || acc.RegionId == "" || acc.InstanceId == "" || acc.ShutdownMode == "" || acc.ThresholdGB <= 0 {
			log.Fatalf("account[%d]: missing required fields", i)
		}
	}

	for _, acc := range cfg.Accounts {
		if err := acc.process(cfg.Webhook); err != nil {
			log.Printf("⚠️  [%s] %v", acc.InstanceId, err)
		}
	}
}
