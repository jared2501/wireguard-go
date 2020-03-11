/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/device/tokenbucket"
	"github.com/tailscale/wireguard-go/tai64n"
	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

type handshakeState int

const (
	HandshakeZeroed = handshakeState(iota)
	HandshakeInitiationCreated
	HandshakeInitiationConsumed
	HandshakeResponseCreated
	HandshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case HandshakeZeroed:
		return "HandshakeZeroed"
	case HandshakeInitiationCreated:
		return "HandshakeInitiationCreated"
	case HandshakeInitiationConsumed:
		return "HandshakeInitiationConsumed"
	case HandshakeResponseCreated:
		return "HandshakeResponseCreated"
	case HandshakeResponseConsumed:
		return "HandshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 148                                           // size of handshake initiation message
	MessageResponseSize        = 92                                            // size of response message
	MessageCookieReplySize     = 64                                            // size of cookie reply message
	MessageTransportHeaderSize = 16                                            // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                          // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                         // size of largest handshake related message
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral wgcfg.Key
	Static    [wgcfg.KeySize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral wgcfg.Key
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + poly1305.TagSize]byte
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [blake2s.Size]byte  // hash value
	chainKey                  [blake2s.Size]byte  // chain key
	presharedKey              wgcfg.SymmetricKey  // psk
	localEphemeral            wgcfg.PrivateKey    // ephemeral secret key
	localIndex                uint32              // used to clear hash-table
	remoteIndex               uint32              // index for sending
	remoteStatic              wgcfg.Key           // long term key
	remoteEphemeral           wgcfg.Key           // ephemeral public key
	precomputedStaticStatic   [wgcfg.KeySize]byte // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	initiationLimit           tokenbucket.TokenBucket
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = HandshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

/* Do basic precomputations
 */
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errors.New("static shared secret is zero")
	}

	// create ephemeral key

	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = wgcfg.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	// assign index

	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)

	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: handshake.localEphemeral.Public(),
		Sender:    handshake.localIndex,
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key

	func() {
		var key [chacha20poly1305.KeySize]byte
		ss := handshake.localEphemeral.SharedSecret(handshake.remoteStatic)
		KDF2(
			&handshake.chainKey,
			&key,
			handshake.chainKey[:],
			ss[:],
		)
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Static[:0], ZeroNonce[:], device.staticIdentity.publicKey[:], handshake.hash[:])
	}()
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp

	timestamp := tai64n.Now()
	func() {
		var key [chacha20poly1305.KeySize]byte
		KDF2(
			&handshake.chainKey,
			&key,
			handshake.chainKey[:],
			handshake.precomputedStaticStatic[:],
		)
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])
	}()

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = HandshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		device.log.Debug.Printf("ConsumeMessageInitiation: not an initiation message")
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static key

	var err error
	var peerPK wgcfg.Key
	func() {
		var key [chacha20poly1305.KeySize]byte
		ss := device.staticIdentity.privateKey.SharedSecret(msg.Ephemeral)
		KDF2(&chainKey, &key, chainKey[:], ss[:])
		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	}()
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil {
		k := wgcfg.Key(peerPK)
		device.log.Debug.Printf("ConsumeMessageInitiation: could not find peer by public key: %s", k.ShortString())
		return nil
	}

	handshake := &peer.handshake
	if isZero(handshake.precomputedStaticStatic[:]) {
		device.log.Debug.Printf("ConsumeMessageInitiation: zero precomputed static")
		return nil
	}

	// verify identity

	var timestamp tai64n.Timestamp
	var key [chacha20poly1305.KeySize]byte

	handshake.mutex.RLock()
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		device.log.Debug.Printf("ConsumeMessageInitiation: handshake decrypt failed")
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	now := time.Now()
	flood := !handshake.initiationLimit.CanTake(now)
	handshake.mutex.RUnlock()
	if replay {
		device.log.Debug.Printf("%v - ConsumeMessageInitiation: handshake replay @ %v\n", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Debug.Printf("%v - ConsumeMessageInitiation: handshake flood\n", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	if handshake.state != HandshakeInitiationCreated || device.staticIdentity.publicKey.LessThan(&handshake.remoteStatic) {
		handshake.hash = hash
		handshake.chainKey = chainKey
		handshake.remoteIndex = msg.Sender
		handshake.remoteEphemeral = msg.Ephemeral
		if timestamp.After(handshake.lastTimestamp) {
			handshake.lastTimestamp = timestamp
		}
		handshake.initiationLimit.Take(now)
		handshake.state = HandshakeInitiationConsumed
	} else {
		device.log.Debug.Printf("%v - race: remote initiation IGNORED.\n", peer)
	}

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != HandshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = wgcfg.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.Public()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	func() {
		ss := handshake.localEphemeral.SharedSecret(handshake.remoteEphemeral)
		handshake.mixKey(ss[:])
		ss = handshake.localEphemeral.SharedSecret(handshake.remoteStatic)
		handshake.mixKey(ss[:])
	}()

	// add preshared key

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

	func() {
		aead, _ := chacha20poly1305.New(key[:])
		aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
		handshake.mixHash(msg.Empty[:])
	}()

	handshake.state = HandshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {

		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != HandshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		func() {
			ss := handshake.localEphemeral.SharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		func() {
			ss := device.staticIdentity.privateKey.SharedSecret(msg.Ephemeral)
			mixKey(&chainKey, &chainKey, ss[:])
			setZero(ss[:])
		}()

		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript

		aead, _ := chacha20poly1305.New(key[:])
		_, err := aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = HandshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == HandshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == HandshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = HandshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.sendNonce = 0
	keypair.replayFilter.Init()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.next
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.next = nil
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.next = keypair
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.next != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.next
	keypairs.next = nil
	return true
}
