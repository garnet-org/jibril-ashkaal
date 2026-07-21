package ongoing

import (
	"fmt"
	"testing"
)

func TestHashKey(t *testing.T) {
	tests := []struct {
		name string
		in   uint32
		want string
	}{
		{"zero is empty", 0, ""},
		{"padded to eight", 0x9af2c1, "009af2c1"},
		{"single digit", 0x1, "00000001"},
		{"swapper sentinel", 12345, "00003039"},
		{"seven digits padded", 0xfffffff, "0fffffff"},
		{"eight digits no pad", 0x10000000, "10000000"},
		{"max value", 0xffffffff, "ffffffff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashKey(tt.in)
			if got != tt.want {
				t.Fatalf("hashKey(%#x) = %q, want %q", tt.in, got, tt.want)
			}
			if tt.in != 0 && len(got) != 8 {
				t.Fatalf("hashKey(%#x) width = %d, want 8", tt.in, len(got))
			}
		})
	}
}

func TestHashKeyMatchesFormat(t *testing.T) {
	// The strconv path must stay byte-for-byte identical to the %08x contract
	// it replaced. Sweep across every width up to the padding boundary.
	cases := []uint32{
		0x1, 0xf, 0x10, 0xff, 0x100, 0xfff, 0xffff, 0xfffff,
		0xffffff, 0xfffffff, 0x10000000, 0xffffffff, 0x9af2c1, 12345,
	}

	for _, h := range cases {
		want := fmt.Sprintf("%08x", h)
		got := hashKey(h)
		if got != want {
			t.Fatalf("hashKey(%#x) = %q, want %q", h, got, want)
		}
		if len(got) != 8 {
			t.Fatalf("hashKey(%#x) width = %d, want 8", h, len(got))
		}
	}

	// Zero is the one intentional divergence: no key, not %08x's eight zeros.
	if got := hashKey(0); got != "" {
		t.Fatalf("hashKey(0) = %q, want empty", got)
	}
}

func TestTargetEventKey(t *testing.T) {
	tests := []struct {
		name      string
		eventKind string
		in        uint32
		want      string
	}{
		{"file kind", targetKindFile, 0x12ab34, "file:0012ab34"},
		{"flow kind", targetKindFlow, 0x9af2c1, "flow:009af2c1"},
		{"zero is empty", targetKindFile, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetEventKey(tt.eventKind, tt.in)
			if got != tt.want {
				t.Fatalf("targetEventKey(%q, %#x) = %q, want %q",
					tt.eventKind, tt.in, got, tt.want)
			}
		})
	}
}
