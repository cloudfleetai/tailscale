// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package lanbypass sends selected UDP traffic for a peer's Tailscale address
// straight over a private network the two nodes share, unencrypted and without
// passing through the tun device.
//
// It is meant for overlay networks (VXLAN, Geneve) that run on top of
// Tailscale addresses. A peer is bypassed only while it answers disco pings on
// a private IPv4 endpoint; every other peer, and all other traffic, keeps
// using the encrypted tunnel.
package lanbypass

import (
	"net/netip"
	"time"
)

// PeerSource is the part of magicsock.Conn that Manager uses.
type PeerSource interface {
	LANCandidates() []netip.Addr
	SetOverlayAddrs([]netip.Addr)
	LANPeers(maxAge time.Duration, probe bool, allow func(netip.Addr) bool) map[netip.Addr][]netip.Addr
}
