package service

import (
	"encoding/json"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/infra/conf"
)

func TestSplitHTTPConfigUnmarshal(t *testing.T) {
	// Experiment 1: CamelCase
	jsonCamel := `{"path": "/test", "mode": "stream-up"}`
	config1 := new(conf.SplitHTTPConfig)
	if err := json.Unmarshal([]byte(jsonCamel), config1); err != nil {
		t.Fatalf("Failed to unmarshal camel: %v", err)
	}
	if config1.Path != "/test" {
		t.Errorf("Expected Path '/test', got '%s'", config1.Path)
	}

	// Experiment 2: Standard XHTTP Config
	tests := []struct {
		name            string
		networkSettings string
		expectedPath    string
	}{
		{
			name:            "Standard Path",
			networkSettings: `{"path": "/GunService", "mode": "stream-up"}`,
			expectedPath:    "/GunService",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodeInfo := &api.NodeInfo{
				Trojan: &api.TrojanNode{
					CommonNode: api.CommonNode{
						ServerPort: 443,
					},
					Network:         "xhttp",
					NetworkSettings: json.RawMessage(tt.networkSettings),
				},
			}
			config := &Config{
				Cert: &CertConfig{
					CertFile: "cert",
					KeyFile:  "key",
				},
			}

			streamSettings, err := BuildStreamConfig(nodeInfo.Trojan, config)
			if err != nil {
				t.Fatalf("BuildStreamConfig failed: %v", err)
			}

			if streamSettings == nil {
				t.Fatal("StreamSettings is nil")
			}
			if streamSettings.SplitHTTPSettings == nil {
				t.Fatal("SplitHTTPSettings is nil")
			}
			if streamSettings.SplitHTTPSettings.Path != tt.expectedPath {
				t.Errorf("Expected Path '%s', got '%s'", tt.expectedPath, streamSettings.SplitHTTPSettings.Path)
			}
			if streamSettings.SplitHTTPSettings.Mode != "stream-up" {
				t.Errorf("Expected Mode 'stream-up', got '%s'", streamSettings.SplitHTTPSettings.Mode)
			}
			if *streamSettings.Network != "xhttp" {
				t.Errorf("Expected Network 'xhttp', got '%s'", *streamSettings.Network)
			}
		})
	}
}

func TestSplitHTTPConfigXPadding(t *testing.T) {
	// Experiment 3: Verify XPaddingBytes default or manual setting
	nodeInfo := &api.NodeInfo{
		Trojan: &api.TrojanNode{
			CommonNode: api.CommonNode{
				ServerPort: 443,
			},
			Network:         "xhttp", // Fixed panic: using xhttp to test split http features
			NetworkSettings: json.RawMessage(`{}`),
		},
	}
	config := &Config{}
	streamSettings, err := BuildStreamConfig(nodeInfo.Trojan, config)
	if err != nil {
		t.Fatalf("BuildStreamConfig failed: %v", err)
	}

	splitSettings := streamSettings.SplitHTTPSettings

	// Verify XPaddingBytes default explicit assignment to avoid "invalid x_padding length:0"
	if splitSettings.XPaddingBytes.From != 100 || splitSettings.XPaddingBytes.To != 200 {
		t.Errorf("Expected XPaddingBytes 100-200, got %+v", splitSettings.XPaddingBytes)
	}

	// Verify Build() result
	// Construct a dummy InboundDetourConfig to call Build()
	inboundDetourConfig := &conf.InboundDetourConfig{
		Protocol:      "trojan",
		StreamSetting: streamSettings,
	}
	// We need to set other required fields for Build() to succeed.
	inboundDetourConfig.PortList = &conf.PortList{
		Range: []conf.PortRange{{From: 443, To: 443}},
	}
	inboundDetourConfig.Tag = "test_tag"

	// Settings for trojan are required too
	type TrojanSettings struct {
		Clients []json.RawMessage `json:"clients"`
	}
	settings := TrojanSettings{Clients: []json.RawMessage{}}
	settingsBytes, _ := json.Marshal(settings)
	settingsJSON := json.RawMessage(settingsBytes)
	inboundDetourConfig.Settings = &settingsJSON

	_, err = inboundDetourConfig.Build()
	if err != nil {
		t.Fatalf("Failed to build inbound config: %v", err)
	}
	// Note: checking internal proto fields is hard without reflection or parsing TypedMessage.
	// But if Build succeeds, it implies basic validation passed.
}
