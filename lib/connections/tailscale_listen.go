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
	"net"
	"net/url"
	"time"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/connections/registry"
	"github.com/syncthing/syncthing/lib/nat"
	"github.com/syncthing/syncthing/lib/svcutil"
	"github.com/syncthing/syncthing/lib/sync"
	"github.com/syncthing/syncthing/lib/tailnet"
)

func init() {
	factory := &tailscaleListenerFactory{}
	listeners["tailscale"] = factory
}

type tailscaleListener struct {
	svcutil.ServiceWithError
	onAddressesChangedNotifier

	uri        *url.URL
	cfg        config.Wrapper
	tlsCfg     *tls.Config
	conns      chan internalConn
	factory    listenerFactory
	registry   *registry.Registry
	lanChecker *lanChecker

	mut    sync.RWMutex
	addr   net.Addr
	server net.Listener
}

func (t *tailscaleListener) serve(ctx context.Context) error {
	if !tailnet.IsInitialized() {
		l.Infoln("Listen (BEP/tailscale): Tailscale server not initialized")
		return fmt.Errorf("tailscale server not initialized")
	}

	server := tailnet.GetServer()
	if server == nil {
		l.Infoln("Listen (BEP/tailscale): Tailscale server not available")
		return fmt.Errorf("tailscale server not available")
	}

	// Extract port from URI
	_, portStr, err := net.SplitHostPort(t.uri.Host)
	if err != nil {
		l.Infoln("Listen (BEP/tailscale): Invalid host:port format:", t.uri.Host)
		return err
	}

	// Create listener on the Tailscale network
	listener, err := server.Listen(ctx, "tcp", fmt.Sprintf(":%s", portStr))
	if err != nil {
		l.Infoln("Listen (BEP/tailscale):", err)
		return err
	}
	defer listener.Close()

	// Get the Tailscale IP addresses
	ip4, _ := server.TailscaleIPs()
	if ip4 == nil || len(ip4) == 0 {
		l.Infoln("Listen (BEP/tailscale): No valid Tailscale IPv4 address")
		return fmt.Errorf("no valid tailscale ipv4 address")
	}

	// Create a TCP address with the Tailscale IP and the listener port
	tcpAddr := &net.TCPAddr{
		IP:   ip4,
		Port: listener.Addr().(*net.TCPAddr).Port,
	}

	t.mut.Lock()
	t.addr = tcpAddr
	t.server = listener
	t.mut.Unlock()
	defer func() {
		t.mut.Lock()
		t.addr = nil
		t.server = nil
		t.mut.Unlock()
	}()

	t.notifyAddressesChanged(t)
	defer t.clearAddresses(t)

	t.registry.Register("tailscale", tcpAddr)
	defer t.registry.Unregister("tailscale", tcpAddr)

	l.Infof("Tailscale listener (%v) starting", tcpAddr)
	defer l.Infof("Tailscale listener (%v) shutting down", tcpAddr)

	acceptFailures := 0
	const maxAcceptFailures = 10

	for {
		conn, err := listener.Accept()
		select {
		case <-ctx.Done():
			if err == nil {
				conn.Close()
			}
			return nil
		default:
		}
		if err != nil {
			l.Warnln("Listen (BEP/tailscale): Accepting connection:", err)

			acceptFailures++
			if acceptFailures > maxAcceptFailures {
				// Return to restart the listener, because something
				// seems permanently damaged.
				return err
			}

			// Slightly increased delay for each failure.
			time.Sleep(time.Duration(acceptFailures) * time.Second)
			continue
		}

		acceptFailures = 0
		l.Debugln("Listen (BEP/tailscale): connect from", conn.RemoteAddr())

		tc := tls.Server(conn, t.tlsCfg)
		if err := tlsTimedHandshake(tc); err != nil {
			l.Infoln("Listen (BEP/tailscale): TLS handshake:", err)
			tc.Close()
			continue
		}

		// Tailscale connections are always considered "local" for priority purposes
		priority := t.cfg.Options().ConnectionPriorityTCPLAN
		t.conns <- newInternalConn(tc, connTypeTailscaleServer, true, priority)
	}
}

func (t *tailscaleListener) URI() *url.URL {
	return t.uri
}

func (t *tailscaleListener) WANAddresses() []*url.URL {
	t.mut.RLock()
	defer t.mut.RUnlock()

	if t.addr == nil {
		return nil
	}

	uri := *t.uri
	uri.Host = t.addr.String()
	return []*url.URL{&uri}
}

func (t *tailscaleListener) LANAddresses() []*url.URL {
	return t.WANAddresses()
}

func (t *tailscaleListener) String() string {
	return t.uri.String()
}

func (t *tailscaleListener) Factory() listenerFactory {
	return t.factory
}

func (*tailscaleListener) NATType() string {
	return "tailscale"
}

type tailscaleListenerFactory struct{}

func (f *tailscaleListenerFactory) New(uri *url.URL, cfg config.Wrapper, tlsCfg *tls.Config, conns chan internalConn, natService *nat.Service, registry *registry.Registry, lanChecker *lanChecker) genericListener {
	l := &tailscaleListener{
		uri:        fixupPort(uri, 22000),
		cfg:        cfg,
		tlsCfg:     tlsCfg,
		conns:      conns,
		factory:    f,
		registry:   registry,
		lanChecker: lanChecker,
	}
	l.ServiceWithError = svcutil.AsService(l.serve, l.String())
	return l
}

func (tailscaleListenerFactory) Valid(cfg config.Configuration) error {
	if !cfg.Options.Tailscale.Enabled {
		return errDisabled
	}
	return nil
}
