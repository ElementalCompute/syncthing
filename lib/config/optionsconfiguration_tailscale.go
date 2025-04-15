// Copyright (C) 2024 Danucore AI.
// Author: Ace Harvey
//
// Package config implements configuration handling for Syncthing.
package config

// TailscaleConfiguration holds settings for Tailscale-based device discovery
type TailscaleConfiguration struct {
	Enabled bool     `json:"enabled" xml:"enabled" default:"false"`
	APIKey  string   `json:"apiKey" xml:"apiKey"`
	Tags    []string `json:"tags" xml:"tag"`
	Tailnet string   `json:"tailnet" xml:"tailnet"`
	// AutoAccept determines if devices on the same tailnet are automatically trusted
	AutoAccept bool `json:"autoAccept" xml:"autoAccept" default:"true"`

	// Transport options
	AuthKey string `json:"authKey" xml:"authKey`
	AdvertiseTags []string `json:"advertiseTags" xml:"advertiseTags"`
	ServerEnabled bool `json:"tsServe" xml:"tsServe"`
}