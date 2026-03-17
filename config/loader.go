// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package config

import (
	"fmt"
	"io"
	"os"

	"google.golang.org/protobuf/encoding/protojson"
)

func LoadConfig(filePath string) (*Config, error) {
	jsonFile, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open config file: %w", err)
	}
	defer jsonFile.Close()

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %w", err)
	}

	cfg := &Config{}

	options := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}

	if err := options.Unmarshal(byteValue, cfg); err != nil {
		return nil, fmt.Errorf("could not unmarshal config: %w", err)
	}

	return cfg, nil
}
