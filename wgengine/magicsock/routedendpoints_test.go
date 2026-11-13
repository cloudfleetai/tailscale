// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestSubnetRoutes(t *testing.T) {
	n := (&tailcfg.Node{
		Addresses:  pfx("100.64.0.1/32", "fd7a:115c:a1e0::1/128"),
		AllowedIPs: pfx("100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.244.1.0/24", "0.0.0.0/0", "::/0"),
		Hostinfo:   (&tailcfg.Hostinfo{RoutableIPs: pfx("10.244.1.0/24", "192.168.7.0/24")}).View(),
	}).View()
	if got, want := subnetRoutes(n), pfx("10.244.1.0/24", "192.168.7.0/24"); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestEndpointInsidePeerRoute(t *testing.T) {
	de := &endpoint{
		c:             &Conn{logf: t.Logf},
		endpointState: map[netip.AddrPort]*endpointState{},
		routes:        pfx("10.244.1.0/24"),
	}
	inside := netip.MustParseAddrPort("10.244.1.7:41641")
	outside := netip.MustParseAddrPort("10.0.0.7:41641")

	de.setEndpointsLocked(views.SliceOf([]netip.AddrPort{inside, outside}))
	if _, ok := de.endpointState[inside]; ok {
		t.Errorf("%v from the netmap was kept", inside)
	}
	if _, ok := de.endpointState[outside]; !ok {
		t.Errorf("%v from the netmap was dropped", outside)
	}

	de.addCandidateEndpoint(inside, [12]byte{1})
	if _, ok := de.endpointState[inside]; ok {
		t.Errorf("%v learned from a ping was kept", inside)
	}

	// An endpoint that was fine becomes unusable once the peer routes it.
	de.setBestAddrLocked(addrQuality{epAddr: epAddr{ap: outside}})
	de.routes = pfx("10.0.0.0/24")
	de.setEndpointsLocked(views.SliceOf([]netip.AddrPort{outside}))
	if _, ok := de.endpointState[outside]; ok {
		t.Errorf("%v was kept after the peer started routing it", outside)
	}
	if de.bestAddr.ap.IsValid() {
		t.Errorf("bestAddr still %v", de.bestAddr.ap)
	}
}
