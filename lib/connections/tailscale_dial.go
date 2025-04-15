// Copyright (C) 2024 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package connections

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"time"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/connections/registry"
	"github.com/syncthing/syncthing/lib/protocol"
	"github.com/syncthing/syncthing/lib/tailnet"
)

func init() {
	factory := &tailscaleDialerFactory{}
	dialers["tailscale"] = factory
}

type tailscaleDialer struct {
	commonDialer
}

func (d *tailscaleDialer) Dial(ctx context.Context, _ protocol.DeviceID, uri *url.URL) (internalConn, error) {
	// Ensure Tailscale is initialized
	if !tailnet.IsInitialized() {
		return internalConn{}, fmt.Errorf("tailscale server not initialized")
	}

	server := tailnet.GetServer()
	if server == nil {
		return internalConn{}, fmt.Errorf("tailscale server not available")
	}

	uri = fixupPort(uri, config.DefaultTCPPort)
	l.Debugf("Dial (BEP/tailscale): Dialing %v", uri)

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Use the Tailscale server's Dial method to create a connection
	conn, err := server.Dial(timeoutCtx, "tcp", uri.Host)
	if err != nil {
		l.Debugf("Dial (BEP/tailscale): Error dialing %v: %v", uri, err)
		return internalConn{}, err
	}

	// Apply TLS
	tc := tls.Client(conn, d.tlsCfg)
	err = tlsTimedHandshake(tc)
	if err != nil {
		l.Debugf("Dial (BEP/tailscale): TLS handshake error: %v", err)
		tc.Close()
		return internalConn{}, err
	}

	// All Tailscale connections are considered "local" for priority purposes
	priority := d.lanPriority
	return newInternalConn(tc, connTypeTailscaleClient, true, priority), nil
}

type tailscaleDialerFactory struct{}

func (tailscaleDialerFactory) New(opts config.OptionsConfiguration, tlsCfg *tls.Config, _ *registry.Registry, lanChecker *lanChecker) genericDialer {
	return &tailscaleDialer{
		commonDialer: commonDialer{
			reconnectInterval: time.Duration(opts.ReconnectIntervalS) * time.Second,
			tlsCfg:            tlsCfg,
			lanChecker:        lanChecker,
			lanPriority:       opts.ConnectionPriorityTCPLAN,
			wanPriority:       opts.ConnectionPriorityTCPLAN, // We use LAN priority for all Tailscale connections
			allowsMultiConns:  true,
		},
	}
}

func (tailscaleDialerFactory) AlwaysWAN() bool {
	return false
}

func (tailscaleDialerFactory) Valid(cfg config.Configuration) error {
	if !cfg.Options.Tailscale.Enabled {
		return errDisabled
	}
	return nil
}

func (tailscaleDialerFactory) String() string {
	return "Tailscale Dialer"
}