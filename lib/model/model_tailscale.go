// Copyright (C) 2024 Danucore AI.
// Author: Ace Harvey

package model

import (
	"net"
	"strings"
	"time"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/protocol"
)

// isTailscaleIP checks if an address belongs to the Tailscale network (100.x.x.x)
func isTailscaleIP(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Try using the address as-is if it doesn't have a port
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return strings.HasPrefix(ip.String(), "100.")
}

// shouldAutoAcceptDevice determines if a device should be automatically accepted
// based on Tailscale configuration
func (m *model) shouldAutoAcceptDevice(deviceID protocol.DeviceID, addresses []string) bool {
	// Check if Tailscale is enabled and auto-accept is enabled
	opts := m.cfg.Options()
	if !opts.Tailscale.Enabled || !opts.Tailscale.AutoAccept {
		return false
	}

	// Check if any of the device's addresses are Tailscale addresses
	for _, addr := range addresses {
		if isTailscaleIP(addr) {
			return true
		}
	}

	return false
}

// handleAutoAcceptDevice automatically accepts a device if it meets the criteria
func (m *model) handleAutoAcceptDevice(deviceID protocol.DeviceID, addresses []string) {
	if !m.shouldAutoAcceptDevice(deviceID, addresses) {
		return
	}

	// Create default device configuration
	deviceCfg := config.DeviceConfiguration{
		DeviceID:    deviceID,
		Name:        deviceID.String()[:7], // Use first 7 characters of device ID as name
		Addresses:   addresses,
		Compression: config.CompressionMetadata,
	}

	// Add the device using the Modify method
	waiter, err := m.cfg.Modify(func(cfg *config.Configuration) {
		cfg.Devices = append(cfg.Devices, deviceCfg)
	})
	if err != nil {
		l.Warnln("Failed to add Tailscale device:", err)
		return
	}
	waiter.Wait()
	if err := m.cfg.Save(); err != nil {
		l.Warnln("Failed to save config after adding Tailscale device:", err)
	}

	// Start a goroutine to share the default folder with the device after a delay
	go m.shareDefaultFolderAfterDelay(deviceID)
}

// shareDefaultFolderAfterDelay waits for 15 seconds, then shares the default folder with the device
func (m *model) shareDefaultFolderAfterDelay(deviceID protocol.DeviceID) {
	// Wait for 15 seconds
	time.Sleep(15 * time.Second)

	// Get the default folder
	defaultFolders := m.cfg.FolderList()
	if len(defaultFolders) == 0 {
		l.Warnln("No folders to share with auto-accepted device:", deviceID)
		return
	}

	// Find the first folder that's not paused to share
	var folderToShare config.FolderConfiguration
	folderFound := false
	for _, folder := range defaultFolders {
		if !folder.Paused {
			folderToShare = folder
			folderFound = true
			break
		}
	}

	if !folderFound {
		l.Warnln("No active folders to share with auto-accepted device:", deviceID)
		return
	}

	// Check if the device is already in the folder
	for _, dev := range folderToShare.Devices {
		if dev.DeviceID == deviceID {
			l.Debugln("Device already has access to folder:", folderToShare.ID)
			return
		}
	}

	// Add the device to the folder
	folderToShare.Devices = append(folderToShare.Devices, config.FolderDeviceConfiguration{
		DeviceID: deviceID,
	})

	// Update the folder configuration
	waiter, err := m.cfg.Modify(func(cfg *config.Configuration) {
		cfg.SetFolder(folderToShare)
	})
	if err != nil {
		l.Warnln("Failed to share folder with Tailscale device:", err)
		return
	}
	waiter.Wait()
	if err := m.cfg.Save(); err != nil {
		l.Warnln("Failed to save config after sharing folder with Tailscale device:", err)
	} else {
		l.Infoln("Successfully shared folder", folderToShare.ID, "with auto-accepted device", deviceID)
	}
}