// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import "testing"

func TestIsOverlayLink(t *testing.T) {
	tests := []struct {
		kind, name, uplink string
		want               bool
	}{
		{"veth", "cilium_host", "eth0", true},
		{"vxlan", "cilium_vxlan", "eth0", true},
		{"", "eth0", "eth0", false},
		{"bridge", "br0", "eth0", false},
		{"veth", "eth0", "eth0", false}, // inside a container
	}
	for _, tt := range tests {
		if got := isOverlayLink(tt.kind, tt.name, tt.uplink); got != tt.want {
			t.Errorf("isOverlayLink(%q, %q, %q) = %v, want %v", tt.kind, tt.name, tt.uplink, got, tt.want)
		}
	}
}
