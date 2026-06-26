package ongoing

import "testing"

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
