/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package wgcfg

import "testing"

func TestTunnelNameIsValid(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"", false},
		{"CON", false},
		{"con", false},
		{"lPt8", false},
		{"foo0", true},
		{"ffffffffffffffffffffffffffffffff", true},
		{"fffffffffffffffffffffffffffffffff", false},
		{"FooBar123", true},
		{"123", true},
		{"a_", true},
		{"a=", true},
		{"a+", true},
		{"a.", true},
		{"a-", true},
		{"a/", false},
		{"a\x00", false},
	}
	for _, tt := range tests {
		got := TunnelNameIsValid(tt.name)
		if got != tt.want {
			t.Errorf("for %q, got %v; want %v", tt.name, got, tt.want)
		}
	}
}
