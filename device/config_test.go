package device

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"sort"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
)

func TestConfig(t *testing.T) {
	pk1, err := wgcfg.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ip1, err := wgcfg.ParseCIDR("10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}

	pk2, err := wgcfg.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ip2, err := wgcfg.ParseCIDR("10.0.0.2/32")
	if err != nil {
		t.Fatal(err)
	}

	pk3, err := wgcfg.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ip3, err := wgcfg.ParseCIDR("10.0.0.3/32")
	if err != nil {
		t.Fatal(err)
	}

	cfg1 := &wgcfg.Config{
		PrivateKey: pk1,
		Peers: []wgcfg.Peer{{
			PublicKey:  pk2.Public(),
			AllowedIPs: []wgcfg.CIDR{ip2},
		}},
	}

	cfg2 := &wgcfg.Config{
		PrivateKey: pk2,
		Peers: []wgcfg.Peer{{
			PublicKey:           pk1.Public(),
			AllowedIPs:          []wgcfg.CIDR{ip1},
			PersistentKeepalive: 5,
		}},
	}

	device1 := NewDevice(newNilTun(), &DeviceOptions{
		Logger: NewLogger(LogLevelDebug, "device1"),
	})
	device2 := NewDevice(newNilTun(), &DeviceOptions{
		Logger: NewLogger(LogLevelDebug, "device2"),
	})
	defer device1.Close()
	defer device2.Close()

	cmp := func(t *testing.T, device *Device, want *wgcfg.Config) {
		t.Helper()
		got := device.Config()
		gotStr, err := got.ToUAPI()
		if err != nil {
			t.Errorf("got.ToUAPI(): error: %v", err)
			return
		}
		wantStr, err := want.ToUAPI()
		if err != nil {
			t.Errorf("want.ToUAPI(): error: %v", err)
			return
		}
		if gotStr != wantStr {
			buf := new(bytes.Buffer)
			w := bufio.NewWriter(buf)
			if err := device.IpcGetOperation(w); err != nil {
				t.Errorf("on error, could not IpcGetOperation: %v", err)
			}
			w.Flush()
			t.Errorf("cfg:\n%s\n---- want:\n%s\n---- uapi:\n%s", gotStr, wantStr, buf.String())
		}
	}

	t.Run("device1 config", func(t *testing.T) {
		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)
	})

	t.Run("device2 config", func(t *testing.T) {
		if err := device2.Reconfig(cfg2); err != nil {
			t.Fatal(err)
		}
		cmp(t, device2, cfg2)
	})

	t.Run("device1 modify peer", func(t *testing.T) {
		cfg1.Peers[0].Endpoints = []wgcfg.Endpoint{{
			Host: "1.2.3.4",
			Port: 12345,
		}}
		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)
	})

	t.Run("device1 replace endpoint", func(t *testing.T) {
		cfg1.Peers[0].Endpoints = []wgcfg.Endpoint{
			{Host: "1.1.1.1", Port: 123},
		}
		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)
	})

	t.Run("device1 add new peer", func(t *testing.T) {
		cfg1.Peers = append(cfg1.Peers, wgcfg.Peer{
			PublicKey:  pk3.Public(),
			AllowedIPs: []wgcfg.CIDR{ip3},
		})
		sort.Slice(cfg1.Peers, func(i, j int) bool {
			return cfg1.Peers[i].PublicKey.LessThan(&cfg1.Peers[j].PublicKey)
		})

		device1.peers.RLock()
		originalPeer0 := device1.peers.keyMap[pk2.Public()]
		device1.peers.RUnlock()

		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)

		device1.peers.RLock()
		newPeer0 := device1.peers.keyMap[pk2.Public()]
		device1.peers.RUnlock()

		if originalPeer0 != newPeer0 {
			t.Error("reconfig modified old peer")
		}
	})

	t.Run("device1 remove peer", func(t *testing.T) {
		removeKey := cfg1.Peers[len(cfg1.Peers)-1].PublicKey
		cfg1.Peers = cfg1.Peers[:len(cfg1.Peers)-1]

		if err := device1.Reconfig(cfg1); err != nil {
			t.Fatal(err)
		}
		cmp(t, device1, cfg1)

		device1.peers.RLock()
		removedPeer := device1.peers.keyMap[removeKey]
		device1.peers.RUnlock()

		if removedPeer != nil {
			t.Error("reconfig failed to remove peer")
		}
	})
}

// TODO: replace with a loopback tunnel
type nilTun struct {
	events chan tun.Event
	closed chan struct{}
}

func newNilTun() tun.Device {
	return &nilTun{
		events: make(chan tun.Event),
		closed: make(chan struct{}),
	}
}

func (t *nilTun) File() *os.File         { return nil }
func (t *nilTun) Flush() error           { return nil }
func (t *nilTun) MTU() (int, error)      { return 1420, nil }
func (t *nilTun) Name() (string, error)  { return "niltun", nil }
func (t *nilTun) Events() chan tun.Event { return t.events }

func (t *nilTun) Read(data []byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Write(data []byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Close() error {
	close(t.events)
	close(t.closed)
	return nil
}
