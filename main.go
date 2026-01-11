package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"hiddify-agent/internal/v2rayapi"
)

type Config struct {
	MasterURL          string `yaml:"master_url"`
	NodeName           string `yaml:"node_name"`
	NodeIP             string `yaml:"node_ip"`
	Region             string `yaml:"region"`
	AgentVersion       string `yaml:"agent_version"`
	TokenFile          string `yaml:"token_file"`
	PollIntervalSec    int    `yaml:"poll_interval_sec"`
	ConfigFilePath     string `yaml:"singbox_config_path"`
	SingBoxServiceName string `yaml:"singbox_service_name"`
	V2RayAPIAddr       string `yaml:"v2ray_api_addr"`
	StatsPollSec       int    `yaml:"stats_poll_sec"`
	ReportWindowSec    int    `yaml:"report_window_sec"`
}

type TokenState struct {
	NodeID string `json:"node_id"`
	Token  string `json:"token"`
}

type AgentConfigResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Version int64 `json:"version"`
		Users   []struct {
			UUID      string `json:"uuid"`
			Enable    bool   `json:"enable"`
			ExpireAt  string `json:"expire_at"`
			Protocols struct {
				VLess struct {
					Enabled bool   `json:"enabled"`
					Flow    string `json:"flow"`
					Port    int    `json:"port"`
				} `json:"vless"`
				Shadowsocks struct {
					Enabled  bool   `json:"enabled"`
					Password string `json:"password"`
					Method   string `json:"method"`
					Port     int    `json:"port"`
				} `json:"shadowsocks"`
			} `json:"protocols"`
		} `json:"users"`
		RealityConfig struct {
			PrivateKey string   `json:"private_key"`
			ShortIDs   []string `json:"short_ids"`
			ServerName string   `json:"server_name"`
		} `json:"reality_config"`
		ShadowsocksServerPassword string `json:"shadowsocks_server_password"`
	} `json:"data"`
}

type TrafficItem struct {
	UserUUID      string `json:"user_uuid"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	Connections   int64  `json:"connections"`
}

type TrafficReport struct {
	ReportTime  string        `json:"report_time"`
	WindowStart string        `json:"window_start"`
	WindowEnd   string        `json:"window_end"`
	Traffic     []TrafficItem `json:"traffic"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.PollIntervalSec == 0 {
		c.PollIntervalSec = 60
	}
	if c.StatsPollSec == 0 {
		c.StatsPollSec = 30
	}
	if c.ReportWindowSec == 0 {
		c.ReportWindowSec = 600
	}
	if c.SingBoxServiceName == "" {
		c.SingBoxServiceName = "sing-box"
	}
	if c.TokenFile == "" {
		c.TokenFile = "/var/lib/hiddify-agent/token.json"
	}
	if c.ConfigFilePath == "" {
		c.ConfigFilePath = "/etc/sing-box/config.json"
	}
	if c.V2RayAPIAddr == "" {
		c.V2RayAPIAddr = "127.0.0.1:8080"
	}
	if c.AgentVersion == "" {
		c.AgentVersion = "0.1.0"
	}
	return &c, nil
}

func loadToken(path string) (*TokenState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s TokenState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.NodeID == "" || s.Token == "" {
		return nil, errors.New("invalid token state")
	}
	return &s, nil
}

func saveToken(path string, s *TokenState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func httpJSON(method, url string, headers map[string]string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(respBody))
	}
	if out != nil {
		return json.Unmarshal(respBody, out)
	}
	return nil
}

func register(cfg *Config) (*TokenState, error) {
	payload := map[string]any{
		"node_name": cfg.NodeName,
		"node_ip":   cfg.NodeIP,
		"region":    cfg.Region,
		"version":   cfg.AgentVersion,
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			NodeID string `json:"node_id"`
			Token  string `json:"token"`
		} `json:"data"`
	}
	if err := httpJSON("POST", cfg.MasterURL+"/api/v1/agent/register", nil, payload, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("register failed: %s", resp.Message)
	}
	return &TokenState{NodeID: resp.Data.NodeID, Token: resp.Data.Token}, nil
}

func pullConfig(cfg *Config, token *TokenState) (*AgentConfigResponse, error) {
	var resp AgentConfigResponse
	headers := map[string]string{
		"Authorization": "Bearer " + token.Token,
		"X-Node-ID":      token.NodeID,
	}
	if err := httpJSON("GET", cfg.MasterURL+"/api/v1/agent/config", headers, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("config failed: %s", resp.Message)
	}
	return &resp, nil
}

func writeSingBoxConfig(cfg *Config, c *AgentConfigResponse) error {
	tags := make([]string, 0, len(c.Data.Users))
	vlessPort := 443
	ssPort := 8388
	ssMethod := "2022-blake3-aes-256-gcm"
	for _, u := range c.Data.Users {
		if u.Enable {
			tags = append(tags, u.UUID)
			if u.Protocols.VLess.Port != 0 {
				vlessPort = u.Protocols.VLess.Port
			}
			if u.Protocols.Shadowsocks.Port != 0 {
				ssPort = u.Protocols.Shadowsocks.Port
			}
			if u.Protocols.Shadowsocks.Method != "" {
				ssMethod = u.Protocols.Shadowsocks.Method
			}
		}
	}
	sb := map[string]any{
		"log": map[string]any{"level": "info"},
		"experimental": map[string]any{
			"v2ray_api": map[string]any{
				"listen": cfg.V2RayAPIAddr,
				"stats": map[string]any{
					"enabled": true,
					"users":   tags,
				},
			},
		},
		"inbounds": []any{
			map[string]any{
				"type": "vless",
				"tag":  "vless-in",
				"listen": "0.0.0.0",
				"listen_port": vlessPort,
				"users": func() []any {
					var us []any
					for _, u := range c.Data.Users {
						if !u.Enable {
							continue
						}
						us = append(us, map[string]any{"uuid": u.UUID, "flow": u.Protocols.VLess.Flow, "name": u.UUID})
					}
					return us
				}(),
				"tls": map[string]any{
					"enabled": true,
					"server_name": c.Data.RealityConfig.ServerName,
					"reality": map[string]any{
						"enabled":     true,
						"private_key": c.Data.RealityConfig.PrivateKey,
						"short_id":    c.Data.RealityConfig.ShortIDs[0],
					},
				},
			},
			map[string]any{
				"type": "shadowsocks",
				"tag":  "ss-in",
				"listen": "0.0.0.0",
				"listen_port": ssPort,
				"method": ssMethod,
				"password": c.Data.ShadowsocksServerPassword,
				"users": func() []any {
					var us []any
					for _, u := range c.Data.Users {
						if !u.Enable {
							continue
						}
						us = append(us, map[string]any{"name": u.UUID, "password": u.Protocols.Shadowsocks.Password})
					}
					return us
				}(),
			},
		},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}

	b, err := json.MarshalIndent(sb, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ConfigFilePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(cfg.ConfigFilePath, b, 0o600)
}

func reloadSingBox(service string) error {
	cmd := exec.Command("systemctl", "reload", service)
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmd = exec.Command("systemctl", "restart", service)
		out2, err2 := cmd.CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("reload/restart sing-box failed: %v %s %s", err2, string(out), string(out2))
		}
	}
	return nil
}

var userStatRe = regexp.MustCompile(`^user>>>([^>]+)>>>traffic>>>(uplink|downlink)$`)

type UserCounters struct {
	Up   int64
	Down int64
}

func collectStats(ctx context.Context, addr string, users []string) (map[string]UserCounters, error) {
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := v2rayapi.NewStatsServiceClient(conn)
	resp, err := client.QueryStats(ctx, &v2rayapi.QueryStatsRequest{Reset_: true, Patterns: []string{"user>>>"}})
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, u := range users {
		allowed[u] = true
	}
	out := map[string]UserCounters{}
	for _, s := range resp.Stat {
		m := userStatRe.FindStringSubmatch(s.Name)
		if len(m) != 3 {
			continue
		}
		userID := m[1]
		if !allowed[userID] {
			continue
		}
		c := out[userID]
		if m[2] == "uplink" {
			c.Up += s.Value
		} else {
			c.Down += s.Value
		}
		out[userID] = c
	}
	return out, nil
}

func reportTraffic(cfg *Config, token *TokenState, windowStart, windowEnd time.Time, counters map[string]UserCounters) error {
	items := make([]TrafficItem, 0, len(counters))
	for userID, c := range counters {
		items = append(items, TrafficItem{UserUUID: userID, UploadBytes: c.Up, DownloadBytes: c.Down, Connections: 0})
	}
	payload := TrafficReport{
		ReportTime:  time.Now().UTC().Format(time.RFC3339),
		WindowStart: windowStart.UTC().Format(time.RFC3339),
		WindowEnd:   windowEnd.UTC().Format(time.RFC3339),
		Traffic:     items,
	}
	headers := map[string]string{"Authorization": "Bearer " + token.Token, "X-Node-ID": token.NodeID}
	return httpJSON("POST", cfg.MasterURL+"/api/v1/agent/traffic", headers, payload, nil)
}

func heartbeat(cfg *Config, token *TokenState, singboxVersion string) error {
	payload := map[string]any{
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"status":         "running",
		"singbox_version": singboxVersion,
		"agent_version":  cfg.AgentVersion,
		"system_info":    map[string]any{},
	}
	headers := map[string]string{"Authorization": "Bearer " + token.Token, "X-Node-ID": token.NodeID}
	return httpJSON("POST", cfg.MasterURL+"/api/v1/agent/heartbeat", headers, payload, nil)
}

func main() {
	cfgPath := "/etc/hiddify-agent/config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	token, err := loadToken(cfg.TokenFile)
	if err != nil {
		token, err = register(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = saveToken(cfg.TokenFile, token)
	}

	var lastVersion int64
	windowStart := time.Now().UTC().Truncate(time.Duration(cfg.ReportWindowSec) * time.Second)
	windowCounters := map[string]UserCounters{}
	lastStatsPoll := time.Time{}

	ticker := time.NewTicker(time.Duration(cfg.PollIntervalSec) * time.Second)
	statsTicker := time.NewTicker(time.Duration(cfg.StatsPollSec) * time.Second)
	heartbeatTicker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	defer statsTicker.Stop()
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ticker.C:
			c, err := pullConfig(cfg, token)
			if err != nil {
				fmt.Fprintln(os.Stderr, "pull config:", err)
				continue
			}
			if c.Data.Version != lastVersion {
				if err := writeSingBoxConfig(cfg, c); err != nil {
					fmt.Fprintln(os.Stderr, "write sing-box config:", err)
					continue
				}
				if err := reloadSingBox(cfg.SingBoxServiceName); err != nil {
					fmt.Fprintln(os.Stderr, "reload sing-box:", err)
					continue
				}
				lastVersion = c.Data.Version
			}
		case <-statsTicker.C:
			if time.Since(lastStatsPoll) < time.Duration(cfg.StatsPollSec)*time.Second {
				continue
			}
			lastStatsPoll = time.Now()
			c, err := pullConfig(cfg, token)
			if err != nil {
				continue
			}
			users := make([]string, 0, len(c.Data.Users))
			for _, u := range c.Data.Users {
				if u.Enable {
					users = append(users, u.UUID)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stats, err := collectStats(ctx, cfg.V2RayAPIAddr, users)
			cancel()
			if err != nil {
				fmt.Fprintln(os.Stderr, "collect stats:", err)
				continue
			}
			for k, v := range stats {
				cur := windowCounters[k]
				cur.Up += v.Up
				cur.Down += v.Down
				windowCounters[k] = cur
			}
			if time.Since(windowStart) >= time.Duration(cfg.ReportWindowSec)*time.Second {
				windowEnd := windowStart.Add(time.Duration(cfg.ReportWindowSec) * time.Second)
				_ = reportTraffic(cfg, token, windowStart, windowEnd, windowCounters)
				windowStart = windowEnd
				windowCounters = map[string]UserCounters{}
			}
		case <-heartbeatTicker.C:
			_ = heartbeat(cfg, token, "")
		}
	}
}

func init() {
	_ = uuid.Nil
}
