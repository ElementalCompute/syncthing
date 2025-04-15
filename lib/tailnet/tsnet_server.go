// Copyright (C) 2024 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tailnet provides a global Tailscale connection that can be shared
// between different components of Syncthing.
package tailnet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
	"maps"
	"slices"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/ipn/ipnstate"
)

// TsnetServerImpl implements the TailscaleServer interface using tsnet
type TsnetServerImpl struct {
	server     *tsnet.Server
	localClient *tailscale.LocalClient
	hostname   string
	tailnet    string
	tags       []string
	mu         sync.RWMutex
	ipv4       net.IP
	ipv6       net.IP
	closed     bool
}

// NewTsnetServer creates a new Tailscale server instance using the provided configuration
func NewTsnetServer(cfg Config) (TailscaleServer, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("tailscale is not enabled in configuration")
	}

	if cfg.AuthKey == "" {
		return nil, fmt.Errorf("tailscale auth key is required")
	}

	hostname := cfg.Hostname
	if hostname == "" {
		hostname = "syncthing"
	}
	srv := new(tsnet.Server)
	srv.Hostname = hostname
	srv.AuthKey = cfg.AuthKey
	srv.Ephemeral = true // cleanup!
	srv.Logf = func(format string, args ...any) {
		l.Debugf(format, args...)
	}

	// Configure tailnet-specific options if provided
	if cfg.Tailnet != "" {
		srv.ControlURL = fmt.Sprintf("https://%s.ts.net", cfg.Tailnet)
	}

	// Start the tsnet server
	l.Infof("Starting Tailscale node with hostname %q", hostname)
	if err := srv.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tailscale: %w", err)
	}

	// Get the local client to interact with the local tailscale node
	localClient, err := srv.LocalClient()
	if err != nil {
		srv.Close()
		return nil, fmt.Errorf("failed to get tailscale local client: %w", err)
	}

	impl := &TsnetServerImpl{
		server:     srv,
		localClient: localClient,
		hostname:   hostname,
		tailnet:    cfg.Tailnet,
		tags:       cfg.Tags,
	}

	// Wait for the server to be ready and retrieve IPs
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	status, err := srv.Up(ctx)
	if err != nil {
		srv.Close()
		return nil, fmt.Errorf("failed to bring tailscale node up: %w", err)
	}

	// Store our assigned addresses
	for _, addr := range status.TailscaleIPs {
		if addr.Is4() {
			impl.ipv4 = net.IP(addr.AsSlice())
			l.Infof("Tailscale IPv4: %s", impl.ipv4)
		} else if addr.Is6() {
			impl.ipv6 = net.IP(addr.AsSlice())
			l.Infof("Tailscale IPv6: %s", impl.ipv6)
		}
	}

	// Apply tags if specified
	if len(cfg.Tags) > 0 {
		l.Infof("Setting Tailscale tags: %v", cfg.Tags)
		err := impl.setTags(ctx, cfg.Tags)
		if err != nil {
			l.Warnf("Failed to set Tailscale tags: %v", err)
		}
	}

	l.Infof("Tailscale node is ready")
	return impl, nil
}

// setTags applies the specified tags to the tailscale node
func (t *TsnetServerImpl) setTags(ctx context.Context, tags []string) error {
	_, err := t.localClient.GetPrefs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tailscale preferences: %w", err)
	}

	// Create a masked preferences object that only sets the fields we want to modify
	maskedPrefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ControlURL:    t.server.ControlURL,
			WantRunning:   true,
			AdvertiseTags: tags,
		},
		ControlURLSet:    true,
		WantRunningSet:   true,
		AdvertiseTagsSet: true,
	}

	// Either use EditPrefs directly or apply the edits and update
	_, err = t.localClient.EditPrefs(ctx, maskedPrefs)
	if err != nil {
		return fmt.Errorf("failed to update tailscale preferences: %w", err)
	}

	return nil
}

// Listen creates a listener on the Tailscale network
func (t *TsnetServerImpl) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, fmt.Errorf("tailscale server is closed")
	}
	t.mu.RUnlock()

	l.Debugf("Tailscale listen on %s:%s", network, addr)
	return t.server.Listen(network, addr)
}

// ListenPacket creates a packet listener on the Tailscale network
func (t *TsnetServerImpl) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, fmt.Errorf("tailscale server is closed")
	}
	t.mu.RUnlock()

	l.Debugf("Tailscale listen packet on %s:%s", network, addr)
	return t.server.ListenPacket(network, addr)
}

// Dial connects to the specified address on the Tailscale network
func (t *TsnetServerImpl) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, fmt.Errorf("tailscale server is closed")
	}
	t.mu.RUnlock()

	l.Debugf("Tailscale dial to %s:%s", network, addr)
	return t.server.Dial(ctx, network, addr)
}

// TailscaleIPs returns the IPv4 and IPv6 addresses assigned to this node
func (t *TsnetServerImpl) TailscaleIPs() (ipv4 net.IP, ipv6 net.IP) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ipv4, t.ipv6
}

// Close shuts down the Tailscale connection
func (t *TsnetServerImpl) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	l.Infof("Shutting down Tailscale connection")
	t.closed = true
	return t.server.Close()
}

// RefreshStatus updates the Tailscale IPs by querying the current status
func (t *TsnetServerImpl) RefreshStatus(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return fmt.Errorf("tailscale server is closed")
	}

	status, err := t.localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tailscale status: %w", err)
	}

	// Update our assigned addresses
	t.ipv4 = nil
	t.ipv6 = nil
	
	for _, addr := range status.TailscaleIPs {
		if addr.Is4() {
			t.ipv4 = net.IP(addr.AsSlice())
			l.Debugf("Updated Tailscale IPv4: %s", t.ipv4)
		} else if addr.Is6() {
			t.ipv6 = net.IP(addr.AsSlice())
			l.Debugf("Updated Tailscale IPv6: %s", t.ipv6)
		}
	}

	return nil
}

// GetPeers returns information about other nodes in the tailnet
func (t *TsnetServerImpl) GetPeers(ctx context.Context) ( []*ipnstate.PeerStatus, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, fmt.Errorf("tailscale server is closed")
	}
	t.mu.RUnlock()

	status, err := t.localClient.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tailscale status: %w", err)
	}

	vals := slices.Collect(maps.Values(status.Peer))
	return vals, nil
}

// WhoIs returns information about the node with the given IP address
func (t *TsnetServerImpl) WhoIs(ctx context.Context, ip netip.Addr) (*apitype.WhoIsResponse, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, fmt.Errorf("tailscale server is closed")
	}
	t.mu.RUnlock()

	return t.localClient.WhoIs(ctx, ip.String())
}

// IsAvailable checks if the Tailscale server is available and connected
func (t *TsnetServerImpl) IsAvailable(ctx context.Context) bool {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return false
	}
	t.mu.RUnlock()

	status, err := t.localClient.Status(ctx)
	if err != nil {
		return false
	}

	return status.BackendState == "Running"
}