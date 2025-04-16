// Copyright (C) 2024 Danucore AI.
// Author: Ace Harvey
//
// Package discover implements device discovery mechanisms for Syncthing.
package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/syncthing/syncthing/lib/events"
	"github.com/syncthing/syncthing/lib/logger"
	"github.com/syncthing/syncthing/lib/protocol"
	"github.com/syncthing/syncthing/lib/tailnet"
)

// TailscaleDiscovery implements the Finder interface using Tailscale's API
type TailscaleDiscovery struct {
	apiKey          string
	tag             string
	addrList        AddressLister
	evLogger        events.Logger
	cache           map[protocol.DeviceID]CacheEntry
	lastError       error
	mut             sync.RWMutex
	healthPort      int
	healthPath      string
	healthCheck     bool
	tailnet         string
	logger          logger.Logger
	announcePort    int
	announcePath    string
	myID            protocol.DeviceID
	httpServer      *http.Server
	tsnetServer     tailnet.TailscaleServer // Tailscale server
	tsnetListener   net.Listener            // Listener for the announcement service
}

// NewTailscale creates a new TailscaleDiscovery instance using an existing Tailscale server
func NewTailscale(apiKey, tag, tailnet string, addrList AddressLister, evLogger events.Logger, myID protocol.DeviceID, ts tailnet.TailscaleServer) *TailscaleDiscovery {
	logger := logger.New()
	logger.Infof("New tailscale discovery initialised, settings received: %s, %s, %s", apiKey, tag, tailnet)
	logger.Infof("Health check settings: enabled=%v, port=%d, path=%s", true, 8384, "/rest/noauth/health")
	
	d := &TailscaleDiscovery{
		apiKey:       apiKey,
		tag:          tag,
		tailnet:      tailnet,
		addrList:     addrList,
		evLogger:     evLogger,
		cache:        make(map[protocol.DeviceID]CacheEntry),
		healthPort:   8384,
		healthPath:   "/rest/noauth/health",
		healthCheck:  true,
		logger:       logger,
		announcePort: 8386,
		announcePath: "/syncthing/announce",
		myID:         myID,
		tsnetServer:  ts,
	}
	
	// Start the announcement server
	if err := d.startAnnouncementServer(); err != nil {
		d.logger.Infof("Failed to start announcement server: %v", err)
		// Continue anyway, as we can still use the discovery functionality
	}
	
	return d
}

// startAnnouncementServer initializes and starts the HTTP server for device announcements
func (d *TailscaleDiscovery) startAnnouncementServer() error {
	mux := http.NewServeMux()
	
	// Add the announcement endpoint
	mux.HandleFunc(d.announcePath, func(w http.ResponseWriter, r *http.Request) {
		d.logger.Infof("Received announce request from %s", r.RemoteAddr)
		
		// Return device ID as JSON
		w.Header().Set("Content-Type", "application/json")
		response := struct {
			DeviceID string `json:"device_id"`
		}{
			DeviceID: d.myID.String(),
		}
		
		if err := json.NewEncoder(w).Encode(response); err != nil {
			d.logger.Infof("Error encoding announcement response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		
		d.logger.Infof("Sent device ID %s to requester %s", d.myID, r.RemoteAddr)
	})
	
	// Create listener using the tsnet server
	var err error
	ipv4, _ := d.tsnetServer.TailscaleIPs()
	d.tsnetListener, err = d.tsnetServer.Listen(context.Background(), "tcp", fmt.Sprintf("%s:%d", ipv4.String(), d.announcePort))
	if err != nil {
		return fmt.Errorf("failed to create tsnet listener on port %d: %v", d.announcePort, err)
	}
	
	d.httpServer = &http.Server{
		Handler: mux,
	}
	
	go func() {
		d.logger.Infof("Starting announcement server on port %d", d.announcePort)
		if err := d.httpServer.Serve(d.tsnetListener); err != nil && err != http.ErrServerClosed {
			d.logger.Infof("Announcement server error: %v", err)
		}
	}()
	
	return nil
}

// Stop gracefully shuts down the HTTP server
func (d *TailscaleDiscovery) Stop() error {
	if d.httpServer != nil {
		d.logger.Infof("Shutting down announcement server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return d.httpServer.Shutdown(ctx)
	}
	return nil
}

// Lookup implements the Finder interface
func (d *TailscaleDiscovery) Lookup(ctx context.Context, deviceID protocol.DeviceID) ([]string, error) {
	d.logger.Infof("Lookup called for device: %s", deviceID)
	
	d.mut.Lock()
	defer d.mut.Unlock()

	// Check cache first
	if ce, ok := d.cache[deviceID]; ok && time.Since(ce.when) < time.Minute*5 {
		d.logger.Infof("Cache hit for device %s. Found %d addresses, age: %s", 
			deviceID, len(ce.Addresses), time.Since(ce.when))
		return ce.Addresses, nil
	}
	
	d.logger.Infof("Cache miss for device %s, performing discovery", deviceID)
	
	addresses, err := d.findPeers(ctx, deviceID)
	if err != nil {
		d.logger.Infof("Error finding peer %s: %v", deviceID, err)
		d.lastError = err
		return nil, err
	}

	d.logger.Infof("Found %d addresses for device %s", len(addresses), deviceID)
	
	// Cache the result
	d.cache[deviceID] = CacheEntry{
		Addresses: addresses,
		when:     time.Now(),
		found:    len(addresses) > 0,
	}
	
	d.logger.Infof("Updated cache for device %s, found=%v", deviceID, len(addresses) > 0)

	return addresses, nil
}

func (d *TailscaleDiscovery) findPeers(ctx context.Context, targetID protocol.DeviceID) ([]string, error) {
	d.logger.Infof("Finding peer with ID=%s, tag=%s, tailnet=%s", targetID, d.tag, d.tailnet)
	
	if d.apiKey == "" {
		d.logger.Infof("Tailscale API key not provided")
		return nil, fmt.Errorf("tailscale api key not provided")
	}

	apiURL := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices?fields=all", d.tailnet)
	d.logger.Infof("Making API request to: %s", apiURL)
	
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		d.logger.Infof("Failed to create request: %v", err)
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+d.apiKey)
	d.logger.Infof("Added authorization header")

	client := &http.Client{Timeout: 10 * time.Second}
	d.logger.Infof("Sending request with timeout of 10 seconds")
	resp, err := client.Do(req)
	if err != nil {
		d.logger.Infof("Request failed: %v", err)
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()
	
	d.logger.Infof("Received response with status code: %d", resp.StatusCode)
	
	if resp.StatusCode != http.StatusOK {
		d.logger.Infof("Non-OK response: %d %s", resp.StatusCode, resp.Status)
		return nil, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	var response struct {
		Devices []struct {
			Addresses []string `json:"addresses"`
			Name      string   `json:"name"`
			LastSeen  string   `json:"lastSeen"`
			Tags      []string `json:"tags"`
		} `json:"devices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		d.logger.Infof("Failed to decode response: %v", err)
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	d.logger.Infof("Successfully decoded response with %d devices", len(response.Devices))
	
	now := time.Now()
	var peerIPs []string
	expectedTag := "tag:" + d.tag
	
	d.logger.Infof("Looking for devices with tag: %s", expectedTag)

	// Get our own Tailscale IPs so we can use direct Tailscale connections
	localIPv4, _ := d.tsnetServer.TailscaleIPs()
	if localIPv4 == nil || len(localIPv4) == 0 {
		d.logger.Infof("Warning: Could not determine local Tailscale IP address")
	} else {
		d.logger.Infof("Local Tailscale IP: %s", localIPv4.String())
	}

	// We'll check all devices with the right tag
	for i, device := range response.Devices {
		d.logger.Infof("Checking device %d: %s, tags: %v", i, device.Name, device.Tags)
		
		// Skip device if it doesn't have the right tag
		hasTag := false
		for _, tag := range device.Tags {
			if tag == expectedTag {
				hasTag = true
				d.logger.Infof("Device %s has matching tag %s", device.Name, expectedTag)
				break
			}
		}
		
		if !hasTag {
			d.logger.Infof("Device %s doesn't have required tag, skipping", device.Name)
			continue
		}
		
		// Check if the device has been seen recently
		lastSeen, err := time.Parse(time.RFC3339, device.LastSeen)
		if err != nil {
			d.logger.Infof("Failed to parse lastSeen time for device %s: %v", device.Name, err)
			continue
		}
		
		timeSinceLastSeen := now.Sub(lastSeen)
		d.logger.Infof("Device %s was last seen %s ago", device.Name, timeSinceLastSeen)
		
		if timeSinceLastSeen >= 5*time.Minute {
			d.logger.Infof("Device %s was last seen more than 5 minutes ago, skipping", device.Name)
			continue
		}
		
		// Find a suitable Tailscale address for this device
		d.logger.Infof("Checking %d addresses for device %s", len(device.Addresses), device.Name)
		
		var tailscaleAddr string
		for _, addr := range device.Addresses {
			if strings.HasPrefix(addr, "100.") {
				tailscaleAddr = addr
				d.logger.Infof("Found Tailscale address for device %s: %s", device.Name, addr)
				break
			}
		}
		
		if tailscaleAddr == "" {
			d.logger.Infof("No suitable Tailscale address found for device %s", device.Name)
			continue
		}
		
		// Now query the device's announcement endpoint to check if it's the target device
		announceURL := fmt.Sprintf("http://%s:%d%s", tailscaleAddr, d.announcePort, d.announcePath)
		d.logger.Infof("Querying announcement endpoint: %s", announceURL)
		
		// Use the tsnet server to dial directly over Tailscale
		announceCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := d.tsnetServer.Dial(announceCtx, "tcp", fmt.Sprintf("%s:%d", tailscaleAddr, d.announcePort))
		cancel()
		
		if err != nil {
			d.logger.Infof("Failed to dial announcement endpoint for %s: %v", device.Name, err)
			continue
		}
		
		// Create HTTP client that uses our tsnet dialed connection
		announceReq, err := http.NewRequest("GET", fmt.Sprintf("http://%s:%d%s", tailscaleAddr, d.announcePort, d.announcePath), nil)
		if err != nil {
			d.logger.Infof("Failed to create announcement request: %v", err)
			conn.Close()
			continue
		}
		
		// Use a transport that only uses our single connection
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		}
		announceClient := &http.Client{Transport: transport}
		
		announceResp, err := announceClient.Do(announceReq)
		if err != nil {
			d.logger.Infof("Failed to query announcement endpoint for %s: %v", device.Name, err)
			conn.Close()
			continue
		}
		
		if announceResp.StatusCode != http.StatusOK {
			d.logger.Infof("Device %s returned non-OK status from announcement endpoint: %d", 
				device.Name, announceResp.StatusCode)
			announceResp.Body.Close()
			conn.Close()
			continue
		}
		
		var announceData struct {
			DeviceID string `json:"device_id"`
		}
		
		if err := json.NewDecoder(announceResp.Body).Decode(&announceData); err != nil {
			d.logger.Infof("Failed to decode announcement response from %s: %v", device.Name, err)
			announceResp.Body.Close()
			conn.Close()
			continue
		}
		
		announceResp.Body.Close()
		conn.Close()
		
		d.logger.Infof("Device %s announced ID: %s", device.Name, announceData.DeviceID)
		
		// Check if this is the device we're looking for
		announcedID, err := protocol.DeviceIDFromString(announceData.DeviceID)
		if err != nil {
			d.logger.Infof("Failed to parse announced device ID from %s: %v", device.Name, err)
			continue
		}
		
		if announcedID != targetID {
			d.logger.Infof("Device %s has ID %s, not our target %s", 
				device.Name, announcedID, targetID)
			continue
		}
		
		d.logger.Infof("Found target device %s at address %s", targetID, tailscaleAddr)
		
		// If we reached here, this is our target device
		// Now check if it's healthy before adding its address
		if d.healthCheck {
			d.logger.Infof("Performing health check for %s", tailscaleAddr)
			if d.checkHealth(tailscaleAddr) {
				d.logger.Infof("Health check passed for %s", tailscaleAddr)
				// Add TCP address
				tcpAddr := fmt.Sprintf("tailscale://%s:%s", tailscaleAddr, "22000")
				d.logger.Infof("Adding TCP address: %s", tcpAddr)
				peerIPs = append(peerIPs, tcpAddr)
				
				// QUIC support commented out
				//quicAddr := fmt.Sprintf("quic://%s:%d", tailscaleAddr, d.healthPort)
				//d.logger.Infof("Adding QUIC address: %s", quicAddr)
				//peerIPs = append(peerIPs, quicAddr)
			} else {
				d.logger.Infof("Health check failed for %s, skipping", tailscaleAddr)
			}
		} else {
			d.logger.Infof("Health check disabled, adding address without verification")
			tcpAddr := fmt.Sprintf("tailscale://%s:%s", tailscaleAddr, "22000")
			d.logger.Infof("Adding TCP address: %s", tcpAddr)
			peerIPs = append(peerIPs, tcpAddr)
			
			// QUIC support commented out
			//quicAddr := fmt.Sprintf("quic://%s:%d", tailscaleAddr, d.healthPort)
			//d.logger.Infof("Adding QUIC address: %s", quicAddr)
			//peerIPs = append(peerIPs, quicAddr)
		}
		
		// Since we found our target device, we can break out of the loop
		break
	}

	d.logger.Infof("Discovery complete, found %d peer addresses for %s", len(peerIPs), targetID)
	return peerIPs, nil
}

func (d *TailscaleDiscovery) checkHealth(addr string) bool {
	healthURL := fmt.Sprintf("http://%s:%d%s", addr, d.healthPort, d.healthPath)
	d.logger.Infof("Checking health at URL: %s", healthURL)
	
	// Use tsnet for the health check
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	conn, err := d.tsnetServer.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", addr, d.healthPort))
	if err != nil {
		d.logger.Infof("Health check dial failed for %s: %v", addr, err)
		return false
	}
	defer conn.Close()
	
	// Create a transport that uses our tsnet connection
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	
	req, err := http.NewRequest("GET", healthURL, nil)
	if err != nil {
		d.logger.Infof("Failed to create health check request: %v", err)
		return false
	}
	
	resp, err := client.Do(req)
	if err != nil {
		d.logger.Infof("Health check failed for %s: %v", addr, err)
		return false
	}
	defer resp.Body.Close()
	
	d.logger.Infof("Health check for %s returned status code: %d", addr, resp.StatusCode)
	return resp.StatusCode == http.StatusOK
}

// Error implements the Finder interface
func (d *TailscaleDiscovery) Error() error {
	d.mut.RLock()
	defer d.mut.RUnlock()
	d.logger.Infof("Error() called, returning: %v", d.lastError)
	return d.lastError
}

// String implements the Finder interface
func (d *TailscaleDiscovery) String() string {
	result := fmt.Sprintf("TailscaleDiscovery{tag=%q, tailnet=%q}", d.tag, d.tailnet)
	d.logger.Infof("String() called, returning: %s", result)
	return result
}

// Cache implements the Finder interface
func (d *TailscaleDiscovery) Cache() map[protocol.DeviceID]CacheEntry {
	d.mut.RLock()
	defer d.mut.RUnlock()
	d.logger.Infof("Cache() called, returning %d entries", len(d.cache))
	return d.cache
}