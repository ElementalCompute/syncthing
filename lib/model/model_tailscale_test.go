// Copyright (C) 2024 Danucore AI.
// Author: Ace Harvey

package model

import (
	"context"
	"testing"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/protocol"
)

func TestShouldAutoAcceptDevice(t *testing.T) {
	m := &model{
		cfg: &testConfig{
			options: config.OptionsConfiguration{
				Tailscale: config.TailscaleConfiguration{
					AutoAccept: true,
				},
			},
		},
	}

	tests := []struct {
		name      string
		addresses []string
		want      bool
	}{
		{
			name:      "tailscale address",
			addresses: []string{"100.1.2.3:22000"},
			want:      true,
		},
		{
			name:      "multiple addresses with tailscale",
			addresses: []string{"192.168.1.1:22000", "100.1.2.3:22000"},
			want:      true,
		},
		{
			name:      "non-tailscale address",
			addresses: []string{"192.168.1.1:22000"},
			want:      false,
		},
		{
			name:      "empty addresses",
			addresses: []string{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.shouldAutoAcceptDevice(protocol.DeviceID{}, tt.addresses); got != tt.want {
				t.Errorf("shouldAutoAcceptDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

// testConfig implements a minimal config.Wrapper for testing
type testConfig struct {
	config.Configuration
	options config.OptionsConfiguration
}

func (c *testConfig) ConfigPath() string                                      { return "" }
func (c *testConfig) RequiresRestart() bool                                  { return false }
func (c *testConfig) Save() error                                            { return nil }
func (c *testConfig) Subscribe(config.Committer) config.Configuration        { return c.Configuration }
func (c *testConfig) Unsubscribe(config.Committer)                          {}
func (c *testConfig) GUI() config.GUIConfiguration                          { return config.GUIConfiguration{} }
func (c *testConfig) LDAP() config.LDAPConfiguration                        { return config.LDAPConfiguration{} }
func (c *testConfig) Options() config.OptionsConfiguration                   { return c.options }
func (c *testConfig) DefaultFolder() config.FolderConfiguration             { return config.FolderConfiguration{} }
func (c *testConfig) DefaultDevice() config.DeviceConfiguration             { return config.DeviceConfiguration{} }
func (c *testConfig) DefaultIgnores() config.Ignores                        { return config.Ignores{} }
func (c *testConfig) Folder(string) (config.FolderConfiguration, bool)      { return config.FolderConfiguration{}, false }
func (c *testConfig) Device(protocol.DeviceID) (config.DeviceConfiguration, bool) { return config.DeviceConfiguration{}, false }
func (c *testConfig) Modify(config.ModifyFunction) (config.Waiter, error)   { return nil, nil }
func (c *testConfig) FolderList() []config.FolderConfiguration             { return nil }
func (c *testConfig) DeviceList() []config.DeviceConfiguration             { return nil }
func (c *testConfig) Folders() map[string]config.FolderConfiguration       { return nil }
func (c *testConfig) Devices() map[protocol.DeviceID]config.DeviceConfiguration { return nil }
func (c *testConfig) IgnoredDevices() []config.ObservedDevice              { return nil }
func (c *testConfig) IgnoredDevice(protocol.DeviceID) bool                 { return false }
func (c *testConfig) IgnoredFolder(protocol.DeviceID, string) bool         { return false }
func (c *testConfig) FolderPasswords(protocol.DeviceID) map[string]string  { return nil }
func (c *testConfig) RemoveFolder(string) (config.Waiter, error)           { return nil, nil }
func (c *testConfig) RemoveDevice(protocol.DeviceID) (config.Waiter, error) { return nil, nil }
func (c *testConfig) MyID() protocol.DeviceID                               { return protocol.DeviceID{} }
func (c *testConfig) RawCopy() config.Configuration                         { return c.Configuration }
func (c *testConfig) Serve(ctx context.Context) error                       { return nil }