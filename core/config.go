// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package core

import (
	"encoding/json"
	"os"
)

type Peer struct {
	Name   string `json:"name"`
	Addr   string `json:"addr"`
	PubKey string `json:"pub_key"`
}

type Config struct {
	Mode       string `json:"mode"`
	ListenAddr string `json:"listen_addr"`
	SocksAddr  string `json:"socks_addr"`
	DecoyURL   string `json:"decoy_url"`
	PrivateKey string `json:"private_key"`
	Peers      []Peer `json:"peers"`
}

var GlobalConfig Config

func LoadConfig(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(file, &GlobalConfig)
}

func GetFastestPeer() *Peer {
	if len(GlobalConfig.Peers) == 0 {
		return nil
	}
	return &GlobalConfig.Peers[0]
}
