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
	"net"
	"sync"

	"github.com/syncthing/syncthing/lib/logger"
)

var (
	l = logger.DefaultLogger.NewFacility("tailnet", "Tailscale integration")

	// Global Tailscale server instance
	globalServer     TailscaleServer
	globalServerLock sync.RWMutex
)

// Config holds the configuration for a Tailscale server
type Config struct {
	Enabled  bool
	AuthKey  string
	Hostname string
	Tailnet  string
	Tags     []string
}

// TailscaleServer defines the interface for a Tailscale server
type TailscaleServer interface {
	// Listen creates a listener on the Tailscale network
	Listen(ctx context.Context, network, addr string) (net.Listener, error)

	// ListenPacket creates a packet listener on the Tailscale network
	ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error)

	// Dial connects to the specified address on the Tailscale network
	Dial(ctx context.Context, network, addr string) (net.Conn, error)

	// TailscaleIPs returns the IPv4 and IPv6 addresses assigned to this node
	TailscaleIPs() (ipv4 net.IP, ipv6 net.IP)

	// Close shuts down the Tailscale connection
	Close() error

	IsEnabled() bool
}

// SetServer sets the global Tailscale server instance
func SetServer(server TailscaleServer) {
	globalServerLock.Lock()
	defer globalServerLock.Unlock()
	globalServer = server
}

// GetServer returns the global Tailscale server instance
func GetServer() TailscaleServer {
	globalServerLock.RLock()
	defer globalServerLock.RUnlock()
	return globalServer
}

// IsInitialized returns true if the global Tailscale server has been initialized
func IsInitialized() bool {
	globalServerLock.RLock()
	defer globalServerLock.RUnlock()
	return globalServer != nil
}

func IsEnabled() bool {
	globalServerLock.RLock()
	defer globalServerLock.RUnlock()
	return globalServer.IsEnabled()
}