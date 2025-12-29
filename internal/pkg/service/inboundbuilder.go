package service

import (
	"encoding/json"
	"fmt"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// InboundBuilder builds Inbound config for Trojan.
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo) (*core.InboundHandlerConfig, error) {
	if nodeInfo.Trojan == nil {
		return nil, fmt.Errorf("node info missing Trojan config")
	}
	trojanInfo := nodeInfo.Trojan

	inboundDetourConfig := &conf.InboundDetourConfig{}

	// Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: uint32(trojanInfo.ServerPort), To: uint32(trojanInfo.ServerPort)}},
	}
	inboundDetourConfig.PortList = portList

	// Tag
	inboundDetourConfig.Tag = fmt.Sprintf("trojan_%d", trojanInfo.ServerPort)

	// Sniffing
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls"},
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	// Protocol
	inboundDetourConfig.Protocol = "trojan"

	// Settings
	type TrojanSettings struct {
		Clients []json.RawMessage `json:"clients"`
	}
	settings := TrojanSettings{
		Clients: []json.RawMessage{},
	}
	settingsBytes, _ := json.Marshal(settings)
	settingsJSON := json.RawMessage(settingsBytes)
	inboundDetourConfig.Settings = &settingsJSON

	// Stream Settings
	// Debug log
	fmt.Printf("Trojan NetworkSettings: %s\n", string(trojanInfo.NetworkSettings))
	streamSetting, err := BuildStreamConfig(trojanInfo, config)
	if err != nil {
		return nil, err
	}
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func BuildStreamConfig(trojanInfo *api.TrojanNode, config *Config) (*conf.StreamConfig, error) {
	streamSetting := new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(trojanInfo.Network)
	streamSetting.Network = &transportProtocol

	// Network Settings
	switch transportProtocol {
	case "tcp":
		if err := buildTCPConfig(trojanInfo, streamSetting); err != nil {
			return nil, err
		}
	case "ws":
		if err := buildWSConfig(trojanInfo, streamSetting); err != nil {
			return nil, err
		}
	case "xhttp":
		if err := buildXHTTPConfig(trojanInfo, streamSetting); err != nil {
			return nil, err
		}
	case "grpc":
		if err := buildGRPCConfig(trojanInfo, streamSetting); err != nil {
			return nil, err
		}
	}

	// Security (TLS) - Trojan usually enforces TLS
	tlsSettings := new(conf.TLSConfig)
	if config.Cert != nil && config.Cert.CertFile != "" { // Check if cert config exists, usually Trojan implies TLS
		streamSetting.Security = "tls"
		tlsSettings.Certs = []*conf.TLSCertConfig{
			{
				CertFile: config.Cert.CertFile,
				KeyFile:  config.Cert.KeyFile,
			},
		}
		streamSetting.TLSSettings = tlsSettings
	} else {
		streamSetting.Security = "none"
	}

	// Ensure XPaddingBytes is set for SplitHTTP to avoid "invalid x_padding length:0"
	if streamSetting.SplitHTTPSettings != nil {
		// Valid padding range 100-1000 bytes. Use JSON unmarshal to ensure correct internal struct fields are set.
		// Try single integer if range fails, or ensure quotes are correct.
		// The error "invalid x_padding length:0" comes from: https://github.com/xtls/xray-core/blob/main/transport/internet/splithttp/splithttp.go
		// It checks xPaddingBytes.Max() <= 0.
		// Let's try setting it to a simple fixed range via JSON string "100-200".
		paddingRange := "100-200"
		quotedRange := fmt.Sprintf(`"%s"`, paddingRange)
		if err := json.Unmarshal([]byte(quotedRange), &streamSetting.SplitHTTPSettings.XPaddingBytes); err != nil {
			fmt.Printf("Failed to set default XPaddingBytes: %s\n", err)
		}
	}

	return streamSetting, nil
}

func buildTCPConfig(trojanInfo *api.TrojanNode, streamSetting *conf.StreamConfig) error {
	if len(trojanInfo.NetworkSettings) > 0 {
		tcpConfig := new(conf.TCPConfig)
		if err := json.Unmarshal(trojanInfo.NetworkSettings, tcpConfig); err == nil {
			streamSetting.TCPSettings = tcpConfig
		}
	}
	return nil
}

func buildWSConfig(trojanInfo *api.TrojanNode, streamSetting *conf.StreamConfig) error {
	if len(trojanInfo.NetworkSettings) > 0 {
		wsConfig := new(conf.WebSocketConfig)
		if err := json.Unmarshal(trojanInfo.NetworkSettings, wsConfig); err != nil {
			return fmt.Errorf("unmarshal ws config error: %w", err)
		}
		streamSetting.WSSettings = wsConfig
	}
	return nil
}

func buildXHTTPConfig(trojanInfo *api.TrojanNode, streamSetting *conf.StreamConfig) error {
	if len(trojanInfo.NetworkSettings) > 0 {
		splitHTTPConfig := new(conf.SplitHTTPConfig)
		if err := json.Unmarshal(trojanInfo.NetworkSettings, splitHTTPConfig); err != nil {
			return fmt.Errorf("unmarshal splithttp config error: %w", err)
		}
		streamSetting.SplitHTTPSettings = splitHTTPConfig
	}
	return nil
}

func buildGRPCConfig(trojanInfo *api.TrojanNode, streamSetting *conf.StreamConfig) error {
	if len(trojanInfo.NetworkSettings) > 0 {
		grpcConfig := new(conf.GRPCConfig)
		if err := json.Unmarshal(trojanInfo.NetworkSettings, grpcConfig); err != nil {
			return fmt.Errorf("unmarshal grpc config error: %w", err)
		}
		streamSetting.GRPCSettings = grpcConfig
	}
	return nil
}
