// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package magicsock

import "net/netip"

func overlayLocalAddrs() []netip.Addr { return nil }
