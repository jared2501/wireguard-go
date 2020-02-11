// SPDX-License-Identifier: MIT

package device

import (
	"fmt"
	"sort"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/ipc"
	"github.com/tailscale/wireguard-go/wgcfg"
)

func (device *Device) Config() *wgcfg.Config {
	// Lock everything.
	device.net.Lock()
	device.net.Unlock()
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()
	device.peers.Lock()
	defer device.peers.Unlock()

	cfg := &wgcfg.Config{
		PrivateKey: device.staticIdentity.privateKey,
		ListenPort: device.net.port,
	}
	for _, peer := range device.peers.keyMap {
		peer.RLock()
		p := wgcfg.Peer{
			PublicKey:           peer.handshake.remoteStatic,
			PresharedKey:        peer.handshake.presharedKey,
			PersistentKeepalive: peer.persistentKeepaliveInterval,
		}
		if peer.endpoint != nil {
			p.Endpoints = peer.endpoint.Addrs()
		}
		for _, ipnet := range device.allowedips.EntriesForPeer(peer) {
			ones, _ := ipnet.Mask.Size()
			cidr := wgcfg.CIDR{
				Mask: uint8(ones),
			}
			copy(cidr.IP.Addr[:], ipnet.IP.To16())
			p.AllowedIPs = append(p.AllowedIPs, cidr)
		}
		peer.RUnlock()

		cfg.Peers = append(cfg.Peers, p)
	}
	sort.Slice(cfg.Peers, func(i, j int) bool {
		return cfg.Peers[i].PublicKey.LessThan(&cfg.Peers[j].PublicKey)
	})

	return cfg
}

// Reconfig replaces the existing device configuration with cfg.
func (device *Device) Reconfig(cfg *wgcfg.Config) (err error) {
	defer func() {
		if err != nil {
			device.RemoveAllPeers()
		}
	}()

	// Remove any currentt peers not in the new configuration.
	device.peers.RLock()
	oldPeers := make(map[wgcfg.Key]bool)
	for k := range device.peers.keyMap {
		oldPeers[k] = true
	}
	device.peers.RUnlock()
	for _, p := range cfg.Peers {
		delete(oldPeers, p.PublicKey)
	}
	for k := range oldPeers {
		device.RemovePeer(k)
	}

	device.staticIdentity.Lock()
	curPrivKey := device.staticIdentity.privateKey
	device.staticIdentity.Unlock()

	if !curPrivKey.Equal(cfg.PrivateKey) {
		if err := device.SetPrivateKey(cfg.PrivateKey); err != nil {
			return err
		}
	}

	device.net.Lock()
	device.net.port = cfg.ListenPort
	device.net.Unlock()

	if err := device.BindUpdate(); err != nil {
		return ErrPortInUse
	}

	// TODO(crawshaw): UAPI supports an fwmark field

	newKeepalivePeers := make(map[wgcfg.Key]*Peer)
	for _, p := range cfg.Peers {
		peer := device.LookupPeer(p.PublicKey)
		if peer == nil {
			peer, err = device.NewPeer(p.PublicKey)
			if err != nil {
				return err
			}
			if p.PersistentKeepalive != 0 && device.isUp.Get() {
				newKeepalivePeers[p.PublicKey] = peer
			}
		}

		if !p.PresharedKey.IsZero() {
			peer.handshake.mutex.Lock()
			peer.handshake.presharedKey = p.PresharedKey
			peer.handshake.mutex.Unlock()
		}

		var ep conn.Endpoint
		if len(p.Endpoints) > 0 {
			str := p.Endpoints[0].String()
			for _, cfgEp := range p.Endpoints[1:] {
				str += "," + cfgEp.String()
			}
			ep, err = device.createEndpoint(p.PublicKey, str)
			if err != nil {
				return err
			}
		}

		peer.Lock()
		peer.endpoint = ep
		peer.persistentKeepaliveInterval = p.PersistentKeepalive
		peer.Unlock()

		device.allowedips.RemoveByPeer(peer)
		for _, allowedIP := range p.AllowedIPs {
			ones := uint(allowedIP.Mask)
			ip := allowedIP.IP.IP()
			if allowedIP.IP.Is4() {
				ip = ip.To4()
			}
			device.allowedips.Insert(ip, ones, peer)
		}
	}

	// Send immediate keepalive if we're turning it on and before it wasn't on.
	for _, peer := range newKeepalivePeers {
		peer.SendKeepalive()
	}

	return nil
}

var ErrPortInUse = fmt.Errorf("wireguard: local port in use: %w", &IPCError{ipc.IpcErrorPortInUse})
