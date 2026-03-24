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
	"sort"
	"strings"
	"time"
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

const quotaGB = 200.0

var httpClient = &http.Client{Timeout: 15 * time.Second}

func aliyunRequest(host, version, action, method string, extra map[string]string, ak, secret string) ([]byte, error) {
	params := map[string]string{
		"Format":           "JSON",
		"Version":          version,
		"AccessKeyId":      ak,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"Action":           action,
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureNonce":    fmt.Sprintf("%d_%d", time.Now().UnixNano(), rand.Int63()),
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

	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(method + "&" + pEncode("/") + "&" + pEncode(canonical)))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	reqURL := fmt.Sprintf("https://%s/?%s&Signature=%s", host, canonical, pEncode(sig))

	var (
		resp *http.Response
		err  error
	)
	if strings.EqualFold(method, "POST") {
		resp, err = httpClient.Post(reqURL, "application/x-www-form-urlencoded", nil)
	} else {
		resp, err = httpClient.Get(reqURL)
	}
	if err != nil {
		return nil, fmt.Errorf("http %s %s: %w", method, action, err)
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
		return nil, fmt.Errorf("API error [%s]: %s", apiErr.Code, apiErr.Message)
	}
	return body, nil
}

func pEncode(s string) string {
	r := url.QueryEscape(s)
	r = strings.ReplaceAll(r, "+", "%20")
	r = strings.ReplaceAll(r, "*", "%2A")
	r = strings.ReplaceAll(r, "%7E", "~")
	return r
}

func isOverseas(region string) bool {
	return !strings.HasPrefix(region, "cn-") || region == "cn-hongkong"
}

func getTrafficGB(acc Account) (float64, error) {
	body, err := aliyunRequest("cdt.aliyuncs.com", "2021-08-13", "ListCdtInternetTraffic", "POST",
		nil, acc.AccessKeyId, acc.AccessKeySecret)
	if err != nil {
		return 0, err
	}

	var res struct {
		TrafficDetails []struct {
			BusinessRegionId string
			Traffic          float64
		}
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return 0, fmt.Errorf("getTrafficGB: %w", err)
	}

	targetOverseas := isOverseas(acc.RegionId)
	var total float64
	for _, d := range res.TrafficDetails {
		if isOverseas(d.BusinessRegionId) == targetOverseas {
			total += d.Traffic
		}
	}
	return total / (1024 * 1024 * 1024), nil
}

func getInstanceStatus(acc Account) (string, error) {
	body, err := aliyunRequest(ecsHost(acc), "2014-05-26", "DescribeInstanceStatus", "GET",
		map[string]string{"RegionId": acc.RegionId, "InstanceId": acc.InstanceId},
		acc.AccessKeyId, acc.AccessKeySecret)
	if err != nil {
		return "", err
	}

	var res struct {
		InstanceStatuses struct {
			InstanceStatus []struct{ Status string }
		}
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("getInstanceStatus: %w", err)
	}

	statuses := res.InstanceStatuses.InstanceStatus
	if len(statuses) == 0 {
		return "", fmt.Errorf("getInstanceStatus: no status returned")
	}
	return statuses[0].Status, nil
}

func controlInstance(acc Account, action string) error {
	apiAction := "StartInstance"
	params := map[string]string{"RegionId": acc.RegionId, "InstanceId": acc.InstanceId}
	if action == "stop" {
		apiAction = "StopInstance"
		if acc.ShutdownMode == "" {
			acc.ShutdownMode = "KeepCharging"
		}
		params["StoppedMode"] = acc.ShutdownMode
	}
	_, err := aliyunRequest(ecsHost(acc), "2014-05-26", apiAction, "GET", params, acc.AccessKeyId, acc.AccessKeySecret)
	return err
}

func ecsHost(acc Account) string {
	return fmt.Sprintf("ecs.%s.aliyuncs.com", acc.RegionId)
}

var webhookClient = &http.Client{Timeout: 10 * time.Second}

func sendWebhook(wh Webhook, message string) {
	if !wh.Enabled || !strings.HasPrefix(wh.URL, "generic://") {
		return
	}
	parsed, err := url.Parse(strings.ReplaceAll(wh.URL, "generic://", "https://"))
	if err != nil {
		log.Printf("webhook: invalid URL: %v", err)
		return
	}

	headers := make(http.Header)
	payload := make(map[string]interface{})
	forwarded := url.Values{}
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
	req, err := http.NewRequest(reqMethod, parsed.String(), bytes.NewBuffer(body))
	if err != nil {
		log.Printf("webhook: build request: %v", err)
		return
	}
	req.Header = headers
	req.Header.Set("Content-Type", contentType)

	resp, err := webhookClient.Do(req)
	if err != nil {
		log.Printf("webhook: send: %v", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

func notify(wh Webhook, msg string) {
	log.Print(msg)
	sendWebhook(wh, msg)
}

func main() {
	cfgPath := flag.String("c", "conf.json", "config file path")
	flag.Parse()

	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}

	for _, acc := range cfg.Accounts {
		if err := processAccount(acc, cfg.Webhook); err != nil {
			log.Printf("⚠️  skipped: %v", err)
		}
	}
}

func processAccount(acc Account, wh Webhook) error {
	traffic, err := getTrafficGB(acc)
	if err != nil {
		return fmt.Errorf("get traffic: %w", err)
	}
	status, err := getInstanceStatus(acc)
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	stats := fmt.Sprintf("%.2f / %.0f GB (%.1f%%)", traffic, quotaGB, (traffic/quotaGB)*100)

	switch {
	case status == "Stopped" && traffic < acc.ThresholdGB:
		if err := controlInstance(acc, "start"); err != nil {
			return fmt.Errorf("start instance: %w", err)
		}
		notify(wh, fmt.Sprintf("🟢 Starting Instance | %s", stats))

	case status == "Running" && traffic >= acc.ThresholdGB:
		if err := controlInstance(acc, "stop"); err != nil {
			return fmt.Errorf("stop instance: %w", err)
		}
		notify(wh, fmt.Sprintf("🔴 Stopping Instance | %s", stats))

	case status == "Running":
		log.Printf("🟢 Instance Running | %s", stats)

	default:
		log.Printf("🔴 Instance Stopped | %s", stats)
	}

	return nil
}
