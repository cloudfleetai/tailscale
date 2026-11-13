// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import "testing"

func TestIsCNIInterface(t *testing.T) {
	for name, want := range map[string]bool{
		"cilium_host":  true,
		"cilium_vxlan": true,
		"lxc_health":   true,
		"lxc12ab34cd":  true,
		"eth0":         false,
		"enp7s0":       false,
		"docker0":      false,
	} {
		if got := isCNIInterface(name); got != want {
			t.Errorf("isCNIInterface(%q) = %v, want %v", name, got, want)
		}
	}
}
