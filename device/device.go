/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/ratelimiter"
	"github.com/tailscale/wireguard-go/rwcancel"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	DeviceRoutineNumberPerCPU     = 3
	DeviceRoutineNumberAdditional = 2
)

type Device struct {
	isUp           AtomicBool // device is (going) up
	isClosed       AtomicBool // device is closed? (acting as guard)
	log            *Logger
	handshakeDone  func(peerKey wgcfg.Key, allowedIPs []net.IPNet)
	skipBindUpdate bool
	createBind     func(uport uint16, device *Device) (conn.Bind, uint16, error)
	createEndpoint func(key [32]byte, s string) (conn.Endpoint, error)

	// synchronized resources (locks acquired in order)

	state struct {
		starting sync.WaitGroup
		stopping sync.WaitGroup
		sync.Mutex
		changing AtomicBool
		current  bool
	}

	net struct {
		starting sync.WaitGroup
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind // bind interface
		netlinkCancel *rwcancel.RWCancel
		port          uint16 // listening port
		fwmark        uint32 // mark value (0 = disabled)
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey wgcfg.PrivateKey
		publicKey  wgcfg.Key
	}

	peers struct {
		sync.RWMutex
		keyMap map[wgcfg.Key]*Peer
	}

	// unprotected / "self-synchronising resources"

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	unexpectedip func(key *wgcfg.Key, ip wgcfg.IP)

	rate struct {
		underLoadUntil atomic.Value
		limiter        ratelimiter.Ratelimiter
	}

	pool struct {
		messageBufferPool        *sync.Pool
		messageBufferReuseChan   chan *[MaxMessageSize]byte
		inboundElementPool       *sync.Pool
		inboundElementReuseChan  chan *QueueInboundElement
		outboundElementPool      *sync.Pool
		outboundElementReuseChan chan *QueueOutboundElement
	}

	queue struct {
		encryption chan *QueueOutboundElement
		decryption chan *QueueInboundElement
		handshake  chan QueueHandshakeElement
	}

	signals struct {
		stop chan struct{}
	}

	tun struct {
		device tun.Device
		mtu    int32
	}
}

/* Converts the peer into a "zombie", which remains in the peer map,
 * but processes no packets and does not exists in the routing table.
 *
 * Must hold device.peers.Mutex
 */
func unsafeRemovePeer(device *Device, peer *Peer, key wgcfg.Key) {
	// stop routing of packets
	device.allowedips.RemoveByPeer(peer)

	// remove from peer map
	delete(device.peers.keyMap, key)
}

func deviceUpdateState(device *Device) {

	// check if state already being updated (guard)

	if device.state.changing.Swap(true) {
		return
	}

	// compare to current state of device

	device.state.Lock()

	newIsUp := device.isUp.Get()

	if newIsUp == device.state.current {
		device.state.changing.Set(false)
		device.state.Unlock()
		return
	}

	// change state of device

	switch newIsUp {
	case true:
		if err := device.BindUpdate(); err != nil {
			device.log.Error.Printf("Unable to update bind: %v\n", err)
			device.isUp.Set(false)
			break
		}
		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Start()
			peer.RLock()
			keepalive := peer.persistentKeepaliveInterval
			peer.RUnlock()

			if keepalive > 0 {
				peer.SendKeepalive()
			}
		}
		device.peers.RUnlock()

	case false:
		device.BindClose()
		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Stop()
		}
		device.peers.RUnlock()
	}

	// update state variables

	device.state.current = newIsUp
	device.state.changing.Set(false)
	device.state.Unlock()

	// check for state change in the mean time

	deviceUpdateState(device)
}

func (device *Device) String() string {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	return device.staticIdentity.publicKey.ShortString()
}

func (device *Device) Up() {

	// closed device cannot be brought up

	if device.isClosed.Get() {
		return
	}

	device.isUp.Set(true)
	deviceUpdateState(device)
}

func (device *Device) Down() {
	device.isUp.Set(false)
	deviceUpdateState(device)
}

func (device *Device) IsUnderLoad() bool {

	// check if currently under load

	now := time.Now()
	underLoad := len(device.queue.handshake) >= UnderLoadQueueSize
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime))
		return true
	}

	// check if recently under load

	until := device.rate.underLoadUntil.Load().(time.Time)
	return until.After(now)
}

func (device *Device) SetPrivateKey(sk wgcfg.PrivateKey) error {
	var peersToStop []*Peer
	defer func() {
		for _, peer := range peersToStop {
			peer.Stop()
		}
	}()

	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equal(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys
	var publicKey wgcfg.Key // allow a zero key here for disabling this device
	if !sk.IsZero() {
		publicKey = sk.Public()
	}

	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equal(publicKey) {
			unsafeRemovePeer(device, peer, key)
			peersToStop = append(peersToStop, peer)
		}
	}

	// update key material

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic = device.staticIdentity.privateKey.SharedSecret(handshake.remoteStatic)
		if isZero(handshake.precomputedStaticStatic[:]) {
			panic("an invalid peer public key made it into the configuration")
		}
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

type DeviceOptions struct {
	Logger *Logger

	// UnexpectedIP is called when a packet is received from a
	// validated peer with an unexpected internal IP address.
	// The packet is then dropped.
	UnexpectedIP func(key *wgcfg.Key, ip wgcfg.IP)

	// HandshakeDone is called every time we complete a peer handshake.
	// TODO(crawshaw): send the *Peer parameter here?
	HandshakeDone func(peerKey wgcfg.Key, allowedIPs []net.IPNet)

	CreateEndpoint func(key [32]byte, s string) (conn.Endpoint, error)
	CreateBind     func(uport uint16) (conn.Bind, uint16, error)
	SkipBindUpdate bool // if true, CreateBind only ever called once
}

func NewDevice(tunDevice tun.Device, opts *DeviceOptions) *Device {
	device := new(Device)

	device.isUp.Set(false)
	device.isClosed.Set(false)

	if opts != nil {
		if opts.Logger != nil {
			device.log = opts.Logger
		}
		if opts.UnexpectedIP != nil {
			device.unexpectedip = opts.UnexpectedIP
		} else {
			device.unexpectedip = func(key *wgcfg.Key, ip wgcfg.IP) {
				device.log.Info.Printf("IPv4 packet with disallowed source address %s from %v", ip, key)
			}
		}
		device.handshakeDone = opts.HandshakeDone
		if opts.CreateEndpoint != nil {
			device.createEndpoint = opts.CreateEndpoint
		} else {
			device.createEndpoint = func(_ [32]byte, s string) (conn.Endpoint, error) {
				return conn.CreateEndpoint(s)
			}
		}
		if opts.CreateBind != nil {
			device.createBind = func(uport uint16, device *Device) (conn.Bind, uint16, error) {
				return opts.CreateBind(uport)
			}
		} else {
			device.createBind = func(uport uint16, device *Device) (conn.Bind, uint16, error) {
				return conn.CreateBind(uport, device)
			}
		}
		device.skipBindUpdate = opts.SkipBindUpdate
	}

	device.tun.device = tunDevice
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Error.Println("Trouble determining MTU, assuming default:", err)
		mtu = DefaultMTU
	}
	device.tun.mtu = int32(mtu)

	device.peers.keyMap = make(map[wgcfg.Key]*Peer)

	device.rate.underLoadUntil.Store(time.Time{})

	device.indexTable.Init()
	device.allowedips.Reset()

	device.PopulatePools()

	// create queues

	device.queue.handshake = make(chan QueueHandshakeElement, QueueHandshakeSize)
	device.queue.encryption = make(chan *QueueOutboundElement, QueueOutboundSize)
	device.queue.decryption = make(chan *QueueInboundElement, QueueInboundSize)

	// prepare signals

	device.signals.stop = make(chan struct{})

	// prepare net

	device.net.port = 0
	device.net.bind = nil

	// start workers

	cpus := runtime.NumCPU()
	device.state.starting.Wait()
	device.state.stopping.Wait()
	device.state.stopping.Add(DeviceRoutineNumberPerCPU*cpus + DeviceRoutineNumberAdditional)
	device.state.starting.Add(DeviceRoutineNumberPerCPU*cpus + DeviceRoutineNumberAdditional)
	for i := 0; i < cpus; i += 1 {
		go device.RoutineEncryption()
		go device.RoutineDecryption()
		go device.RoutineHandshake()
	}

	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	device.state.starting.Wait()

	return device
}

func (device *Device) LookupPeer(pk wgcfg.Key) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

// RemovePeer stops the Peer and removes it from routing.
func (device *Device) RemovePeer(key wgcfg.Key) {
	device.peers.Lock()
	peer := device.peers.keyMap[key]
	if peer != nil {
		unsafeRemovePeer(device, peer, key)
	}
	device.peers.Unlock()

	if peer != nil {
		peer.Stop()
	}
}

func (device *Device) RemoveAllPeers() {
	var peersToStop []*Peer
	defer func() {
		for _, peer := range peersToStop {
			peer.Stop()
		}
	}()

	device.peers.Lock()
	defer device.peers.Unlock()
	for key, peer := range device.peers.keyMap {
		peersToStop = append(peersToStop, peer)
		unsafeRemovePeer(device, peer, key)
	}
	device.peers.keyMap = make(map[wgcfg.Key]*Peer)
}

func (device *Device) FlushPacketQueues() {
	for {
		select {
		case elem, ok := <-device.queue.decryption:
			if ok {
				elem.Drop()
			}
		case elem, ok := <-device.queue.encryption:
			if ok {
				elem.Drop()
			}
		case <-device.queue.handshake:
		default:
			return
		}
	}

}

func (device *Device) Close() {
	if device.isClosed.Swap(true) {
		return
	}

	device.state.starting.Wait()

	device.log.Info.Println("Device closing")
	device.state.changing.Set(true)

	// Grab the state lock while we shut down both the tun device and
	// the userspace socket, and force the device state to Down.
	//
	// Then we must unlock to allow other goroutines to shut down and
	// update state if they so desire, otherwise we end up with
	// infrequent shutdown deadlocks if goroutines are racing each
	// other.
	device.state.Lock()

	device.tun.device.Close()
	device.BindClose()

	device.isUp.Set(false)

	device.state.Unlock()

	close(device.signals.stop)

	device.RemoveAllPeers()

	device.state.stopping.Wait()
	device.FlushPacketQueues()

	device.rate.limiter.Close()

	device.state.changing.Set(false)
	device.log.Info.Println("Interface closed")
}

func (device *Device) Wait() chan struct{} {
	return device.signals.stop
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if device.isClosed.Get() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

func unsafeCloseBind(device *Device) error {
	var err error
	netc := &device.net
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	if netc.bind != nil {
		err = netc.bind.Close()
		netc.bind = nil
	}
	netc.stopping.Wait()
	return err
}

func (device *Device) BindSetMark(mark uint32) error {

	device.net.Lock()
	defer device.net.Unlock()

	// check if modified

	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind

	device.net.fwmark = mark
	if device.isUp.Get() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// clear cached source addresses

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Lock()
		defer peer.Unlock()
		if peer.endpoint != nil {
			peer.endpoint.ClearSrc()
		}
	}
	device.peers.RUnlock()

	return nil
}

func (device *Device) BindUpdate() error {

	device.net.Lock()
	defer device.net.Unlock()

	if device.skipBindUpdate && device.net.bind != nil {
		device.log.Debug.Println("UDP bind update skipped")
		return nil
	}

	// close existing sockets

	if err := unsafeCloseBind(device); err != nil {
		return err
	}

	// open new sockets

	if device.isUp.Get() {

		// bind to new port

		var err error
		netc := &device.net
		netc.bind, netc.port, err = device.createBind(netc.port, device)
		if err != nil {
			netc.bind = nil
			netc.port = 0
			return err
		}
		netc.netlinkCancel, err = device.startRouteListener(netc.bind)
		if err != nil {
			netc.bind.Close()
			netc.bind = nil
			netc.port = 0
			return err
		}

		// set fwmark

		if netc.fwmark != 0 {
			err = netc.bind.SetMark(netc.fwmark)
			if err != nil {
				return err
			}
		}

		// clear cached source addresses

		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Lock()
			defer peer.Unlock()
			if peer.endpoint != nil {
				peer.endpoint.ClearSrc()
			}
		}
		device.peers.RUnlock()

		// start receiving routines

		device.net.starting.Add(conn.ConnRoutineNumber)
		device.net.stopping.Add(conn.ConnRoutineNumber)
		go device.RoutineReceiveIncoming(ipv4.Version, netc.bind)
		go device.RoutineReceiveIncoming(ipv6.Version, netc.bind)
		device.net.starting.Wait()

		device.log.Debug.Println("UDP bind has been updated")
	}

	return nil
}

func (device *Device) BindClose() error {
	device.net.Lock()
	err := unsafeCloseBind(device)
	device.net.Unlock()
	return err
}
