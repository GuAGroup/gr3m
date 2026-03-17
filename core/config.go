// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package core

import (
	"encoding/json"
	"net"
	"os"
	"time"
)

type Peer struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

type Config struct {
	Mode        string `json:"mode"`
	ListenAddr  string `json:"listen_addr"`
	Peers       []Peer `json:"peers"`
	SocksAddr   string `json:"socks_addr"`
	DNSResolver string `json:"dns_resolver"`
	DecoyURL    string `json:"decoy_url"`
}

var GlobalConfig *Config

func LoadConfig(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(file, &GlobalConfig)
}

func GetFastestPeer() string {
	var bestAddr string
	bestRTT := time.Hour

	for _, p := range GlobalConfig.Peers {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", p.Addr, 2*time.Second)
		if err == nil {
			rtt := time.Since(start)
			conn.Close()
			if rtt < bestRTT {
				bestRTT = rtt
				bestAddr = p.Addr
			}
		}
	}
	return bestAddr
}
