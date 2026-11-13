// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package lanbypass

import "tailscale.com/types/logger"

// Manager is a no-op on this platform.
type Manager struct{}

// Start returns nil: the bypass is only implemented on Linux.
func Start(logger.Logf, PeerSource) *Manager { return nil }

// Close does nothing.
func (*Manager) Close() {}
