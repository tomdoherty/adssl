package adssl

import (
	"testing"
)

var (
	HostsToNetIP = hostsToNetIP
)

func TestHostsToNetIP(t *testing.T) {
	got := hostsToNetIP([]string{"localhost"})[0]
	want := "::1"

	if got.String() != want {
		t.Errorf("want %s, got %s", want, got.String())
	}
}
