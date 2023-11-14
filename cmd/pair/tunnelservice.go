package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/danielpaulus/go-ios/ios/opack"
	"github.com/danielpaulus/go-ios/ios/xpc"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"time"
)

func NewTunnelService(host string, port uint32) (*TunnelService, error) {
	h, err := NewHttpConnectionWithAddr(host, port)
	if err != nil {
		return nil, err
	}

	xpcConn, err := NewXpcConnection(h)
	if err != nil {
		return nil, err
	}

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &TunnelService{rw: xpcConn.out, c: xpcConn.c, key: key, messageId: 1}, nil
}

type TunnelService struct {
	rw        io.ReadWriter
	c         io.Closer
	key       *ecdh.PrivateKey
	messageId uint64

	clientEncryption cipher.AEAD
	serverEncryption cipher.AEAD
	cs               *cipherStream
}

func (receiver *TunnelService) Close() error {
	return receiver.c.Close()
}

func (receiver *TunnelService) Pair() error {
	err := xpc.EncodeMessage(receiver.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  createTunnelServiceRequest(),
		Id:    receiver.messageId,
	})
	if err != nil {
		return err
	}
	m, err := xpc.DecodeMessage(receiver.rw)
	if err != nil {
		return err
	}
	receiver.messageId = m.Id + 1
	log.Printf("%+v", m)

	err = xpc.EncodeMessage(receiver.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  createVerifyingDataRequest(receiver.key),
		Id:    receiver.messageId,
	})
	if err != nil {
		return err
	}

	m, err = xpc.DecodeMessage(receiver.rw)
	if err != nil {
		return err
	}
	receiver.messageId = m.Id + 1
	log.Printf("%+v", m)

	//res1 := &plainControlChannelMessageEnvelope{}
	//res1.Decode(m.Body)

	log.Printf("send pair verify failed")
	err = xpc.EncodeMessage(receiver.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  createPairVerifyFailedRequest(),
		Id:    receiver.messageId,
	})
	if err != nil {
		return err
	}
	receiver.messageId += 1

	log.Printf("send pair verify failed")
	err = xpc.EncodeMessage(receiver.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  createSetupManualPairingRequest(),
		Id:    receiver.messageId,
	})
	if err != nil {
		return err
	}

	m, err = xpc.DecodeMessage(receiver.rw)
	if err != nil {
		return err
	}
	log.Printf("%+v", m)
	receiver.messageId = m.Id + 1

	m, err = xpc.DecodeMessage(receiver.rw)
	if err != nil {
		return err
	}
	log.Printf("%+v", m)
	receiver.messageId = m.Id + 1

	c, _ := getChildMap(m.Body, "value", "message", "plain", "_0", "event", "_0", "pairingData", "_0")
	log.Printf("%s", hex.EncodeToString(c["data"].([]byte)))

	devPairingData := new(pairingDataEvent)
	devPairingData.Decode(m.Body)

	devPublicKey := TlvReader(devPairingData.data).ReadCoalesced(TypePublicKey)
	devSaltKey := TlvReader(devPairingData.data).ReadCoalesced(TypeSalt)
	log.Printf("%x", devPublicKey)
	log.Printf("%x", devSaltKey)

	srp, err := NewSrpInfo(devSaltKey, devPublicKey)
	if err != nil {
		return err
	}

	proofTlv := NewTlvBuffer()
	proofTlv.WriteByte(TypeState, 0x3)
	proofTlv.WriteData(TypePublicKey, srp.ClientPublic)
	proofTlv.WriteData(TypeProof, srp.ClientProof)

	err = xpc.EncodeMessage(receiver.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  createClientProofBuffer(proofTlv.Bytes()),
		Id:    receiver.messageId,
	})
	if err != nil {
		return err
	}

	m, err = xpc.DecodeMessage(receiver.rw)
	if err != nil {
		return err
	}
	log.Printf("%+v", m)
	receiver.messageId = m.Id + 1

	//proofEvent := new(plainControlChannelMessageEnvelope)
	proofPairingData := new(pairingDataEvent)
	proofPairingData.Decode(m.Body)

	serverProof := TlvReader(proofPairingData.data).ReadCoalesced(TypeProof)
	verified := srp.VerifyServerProof(serverProof)
	if !verified {
		return fmt.Errorf("could not verify server proof")
	}

	identifier := uuid.New()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	hkdfPairSetup := hkdf.New(sha512.New, srp.SessionKey, []byte("Pair-Setup-Controller-Sign-Salt"), []byte("Pair-Setup-Controller-Sign-Info"))
	buf := bytes.NewBuffer(nil)
	io.CopyN(buf, hkdfPairSetup, 32)
	buf.WriteString(identifier.String())
	buf.Write(public)

	if err != nil {
		return err
	}
	signature := ed25519.Sign(private, buf.Bytes())

	deviceInfo, err := opack.Encode(map[string]interface{}{
		"accountID":                   identifier.String(),
		"altIRK":                      []byte{0x5e, 0xca, 0x81, 0x91, 0x92, 0x02, 0x82, 0x00, 0x11, 0x22, 0x33, 0x44, 0xbb, 0xf2, 0x4a, 0xc8},
		"btAddr":                      "FF:DD:99:66:BB:AA",
		"mac":                         []byte{0xff, 0x44, 0x88, 0x66, 0x33, 0x99},
		"model":                       "MacBookPro18,3",
		"name":                        "host-name",
		"remotepairing_serial_number": "YY9944YY99",
	})

	deviceInfoTlv := NewTlvBuffer()
	deviceInfoTlv.WriteData(TypeSignature, signature)
	deviceInfoTlv.WriteData(TypePublicKey, public)
	deviceInfoTlv.WriteData(TypeIdentifier, []byte(identifier.String()))
	deviceInfoTlv.WriteData(TypeInfo, deviceInfo)

	sessionKeyBuf := bytes.NewBuffer(nil)
	_, err = io.CopyN(sessionKeyBuf, hkdf.New(sha512.New, srp.SessionKey, []byte("Pair-Setup-Encrypt-Salt"), []byte("Pair-Setup-Encrypt-Info")), 32)
	if err != nil {
		return err
	}
	setupKey := sessionKeyBuf.Bytes()

	cipher, err := chacha20poly1305.New(setupKey)
	if err != nil {
		return err
	}

	//deviceInfoLen := len(deviceInfoTlv.Bytes())
	nonce := make([]byte, cipher.NonceSize())
	for x, y := range "PS-Msg05" {
		nonce[4+x] = byte(y)
	}
	//encrypted := make([]byte, deviceInfoLen)
	x := cipher.Seal(nil, nonce, deviceInfoTlv.Bytes(), nil)

	encryptedTlv := NewTlvBuffer()
	encryptedTlv.WriteByte(TypeState, 0x05)
	encryptedTlv.WriteData(TypeEncryptedData, x)

	devInfoEncr := encryptedChannelMessage{
		data:         encryptedTlv.Bytes(),
		originatedBy: "host",
		seqNr:        5,
	}

	err = xpc.EncodeMessage(receiver.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  devInfoEncr.Encode(),
		Id:    receiver.messageId,
	})

	m, err = xpc.DecodeMessage(receiver.rw)
	if err != nil {
		return err
	}
	log.Printf("%+v", m)
	receiver.messageId = m.Id + 1

	var encRes = new(pairingDataEvent)
	encRes.Decode(m.Body)

	encrData := TlvReader(encRes.data).ReadCoalesced(TypeEncryptedData)
	for x, y := range "PS-Msg06" {
		nonce[4+x] = byte(y)
	}
	decrypted, err := cipher.Open(nil, nonce, encrData, nil)

	log.Printf("%s", decrypted)

	err = receiver.setupCiphers(srp.SessionKey)
	if err != nil {
		return err
	}

	receiver.cs = &cipherStream{}

	unlockReq := cipherMessage{
		payload: map[string]interface{}{
			"request": map[string]interface{}{
				"_0": map[string]interface{}{
					"createRemoteUnlockKey": map[string]interface{}{},
				},
			},
		},
		originatedBy: "host",
		sequenceNr:   6,
	}

	unlockReqMsg, err := unlockReq.Encode(receiver.clientEncryption, receiver.cs)
	if err != nil {
		return err
	}

	err = xpc.EncodeMessage(receiver.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  unlockReqMsg,
		Id:    receiver.messageId,
	})

	m, err = xpc.DecodeMessage(receiver.rw)
	if err != nil {
		return err
	}
	log.Printf("%+v", m)
	receiver.messageId = m.Id + 1

	cipherRes := new(cipherMessage)
	cipherRes.Decode(receiver.serverEncryption, receiver.cs, m.Body)

	return nil
}

func (t *TunnelService) CreateTunnelListener() (TunnelInfo, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return TunnelInfo{}, err
	}
	der := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	fmt.Printf("tunnel key: %s\n", hex.EncodeToString(der))
	if err != nil {
		return TunnelInfo{}, err
	}
	listenerReq := cipherMessage{
		payload: map[string]interface{}{
			"request": map[string]interface{}{
				"_0": map[string]interface{}{
					"createListener": map[string]interface{}{
						"key":                   der,
						"transportProtocolType": "tcp",
					},
				},
			},
		},
		originatedBy: "host",
		sequenceNr:   7,
	}

	listenerReqMsg, err := listenerReq.Encode(t.clientEncryption, t.cs)
	if err != nil {
		return TunnelInfo{}, err
	}

	err = xpc.EncodeMessage(t.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  listenerReqMsg,
		Id:    t.messageId,
	})
	if err != nil {
		return TunnelInfo{}, err
	}

	m, err := xpc.DecodeMessage(t.rw)
	if err != nil {
		return TunnelInfo{}, err
	}
	log.Printf("%+v", m)
	t.messageId = m.Id + 1

	listenerRes := new(cipherMessage)
	err = listenerRes.Decode(t.serverEncryption, t.cs, m.Body)
	if err != nil {
		return TunnelInfo{}, err
	}
	log.Infof("Tunnel listener %v", listenerRes.payload)

	createListener, err := getChildMap(listenerRes.payload, "response", "_1", "createListener")
	if err != nil {
		return TunnelInfo{}, err
	}
	port := createListener["port"].(float64)
	devPublicKey := createListener["devicePublicKey"].(string)
	devPK, err := base64.StdEncoding.DecodeString(devPublicKey)
	if err != nil {
		return TunnelInfo{}, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(devPK)
	if err != nil {
		return TunnelInfo{}, err
	}
	return TunnelInfo{
		PrivateKey:      privateKey,
		DevicePublicKey: publicKey,
		TunnelPort:      uint64(port),
	}, nil
}

func (t *TunnelService) setupCiphers(sessionKey []byte) error {
	clientKey := make([]byte, 32)
	_, err := hkdf.New(sha512.New, sessionKey, nil, []byte("ClientEncrypt-main")).Read(clientKey)
	if err != nil {
		return err
	}
	serverKey := make([]byte, 32)
	_, err = hkdf.New(sha512.New, sessionKey, nil, []byte("ServerEncrypt-main")).Read(serverKey)
	if err != nil {
		return err
	}
	t.serverEncryption, err = chacha20poly1305.New(serverKey)
	if err != nil {
		return err
	}
	t.clientEncryption, err = chacha20poly1305.New(clientKey)
	if err != nil {
		return err
	}
	return nil
}

func createTunnelServiceRequest() map[string]interface{} {
	return map[string]interface{}{
		"mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope",
		"value": map[string]interface{}{
			"message": map[string]interface{}{
				"plain": map[string]interface{}{
					"_0": map[string]interface{}{
						"request": map[string]interface{}{
							"_0": map[string]interface{}{
								"handshake": map[string]interface{}{
									"_0": map[string]interface{}{
										"hostOptions": map[string]interface{}{
											"attemptPairVerify": true,
										},
										"wireProtocolVersion": int64(19),
									},
								},
							},
						},
					},
				},
			},
			"originatedBy":   "host",
			"sequenceNumber": uint64(0),
		},
	}
}

func createVerifyingDataRequest(key *ecdh.PrivateKey) map[string]interface{} {
	log.Printf("%v", key.PublicKey().Bytes())

	buf := NewTlvBuffer()
	buf.WriteByte(TypeState, byte(PairStateStartRequest))
	buf.WriteData(TypePublicKey, key.PublicKey().Bytes())

	event := &pairingDataEvent{
		data:            buf.Bytes(),
		originatedBy:    "host",
		sequenceNumber:  1,
		kind:            "verifyManualPairing",
		startNewSession: true,
	}
	return event.Encode()
}

func createPairVerifyFailedRequest() map[string]interface{} {
	return map[string]interface{}{
		"mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope",
		"value": map[string]interface{}{
			"message": map[string]interface{}{
				"plain": map[string]interface{}{
					"_0": map[string]interface{}{
						"event": map[string]interface{}{
							"_0": map[string]interface{}{
								"pairVerifyFailed": map[string]interface{}{},
							},
						},
					},
				},
			},
			"originatedBy":   "host",
			"sequenceNumber": uint64(2),
		},
	}
}

func createSetupManualPairingRequest() map[string]interface{} {
	buf := NewTlvBuffer()
	buf.WriteByte(0x00, 0x00)
	buf.WriteByte(0x06, 0x01)
	event := &pairingDataEvent{
		data:            buf.Bytes(),
		originatedBy:    "host",
		sequenceNumber:  3,
		kind:            "setupManualPairing",
		startNewSession: true,
	}
	return event.Encode()
}

func createClientProofBuffer(b []byte) map[string]interface{} {
	event := &pairingDataEvent{
		data:            b,
		originatedBy:    "host",
		sequenceNumber:  5,
		kind:            "setupManualPairing",
		startNewSession: false,
	}
	return event.Encode()
}

func getChildMap(m map[string]interface{}, keys ...string) (map[string]interface{}, error) {
	if len(keys) == 0 {
		return m, nil
	}
	if c, ok := m[keys[0]].(map[string]interface{}); ok {
		return getChildMap(c, keys[1:]...)
	} else {
		return nil, fmt.Errorf("something went wrong")
	}
}

type encoder interface {
	Encode() map[string]interface{}
}

type decoder interface {
	Decode(map[string]interface{})
}

type coding interface {
	encoder
	decoder
}

type encryptedChannelMessage struct {
	data         []byte
	originatedBy string
	seqNr        uint64
}

func (e encryptedChannelMessage) Encode() map[string]interface{} {
	return map[string]interface{}{
		"mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope",
		"value": map[string]interface{}{
			"message": map[string]interface{}{
				"plain": map[string]interface{}{
					"_0": map[string]interface{}{
						"event": map[string]interface{}{
							"_0": map[string]interface{}{
								"pairingData": map[string]interface{}{
									"_0": map[string]interface{}{
										"data":            e.data,
										"kind":            "setupManualPairing",
										"sendingHost":     "SL-1876",
										"startNewSession": false,
									},
								},
							},
						},
					},
				},
			},
			"originatedBy":   e.originatedBy,
			"sequenceNumber": e.seqNr,
		},
	}
}

type pairingDataEvent struct {
	data            []byte
	originatedBy    string
	sequenceNumber  uint64
	kind            string
	startNewSession bool
}

func (p *pairingDataEvent) Decode(m map[string]interface{}) {
	pairingData, err := getChildMap(m, "value", "message", "plain", "_0", "event", "_0", "pairingData", "_0")
	if err != nil {
		panic(err)
	}
	p.data = pairingData["data"].([]byte)
}

func (p *pairingDataEvent) Encode() map[string]interface{} {
	return map[string]interface{}{
		"mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope",
		"value": map[string]interface{}{
			"message": map[string]interface{}{
				"plain": map[string]interface{}{
					"_0": map[string]interface{}{
						"event": map[string]interface{}{
							"_0": map[string]interface{}{
								"pairingData": map[string]interface{}{
									"_0": map[string]interface{}{
										"data":            p.data,
										"kind":            p.kind,
										"sendingHost":     "SL-1876",
										"startNewSession": p.startNewSession,
									},
								},
							},
						},
					},
				},
			},
			"originatedBy":   p.originatedBy,
			"sequenceNumber": p.sequenceNumber,
		},
	}
}

type cipherCodec interface {
	Encode(c cipher.AEAD, s cipherStream) (map[string]interface{}, error)
	Decode(c cipher.AEAD, s cipherStream, m map[string]interface{}) error
}

type cipherStream struct {
	sequence uint64
	nonce    []byte
}

func (e *cipherStream) Encrypt(c cipher.AEAD, p []byte) []byte {
	e.nonce = e.createNonce(c)
	encrypted := c.Seal(nil, e.nonce, p, nil)
	e.sequence += 1
	return encrypted
}

func (e *cipherStream) Decrypt(c cipher.AEAD, p []byte) ([]byte, error) {
	return c.Open(nil, e.nonce, p, nil)
}

func (e *cipherStream) createNonce(c cipher.AEAD) []byte {
	return append(binary.LittleEndian.AppendUint64(nil, e.sequence), make([]byte, 4)...)
}

type cipherMessage struct {
	payload      map[string]interface{}
	originatedBy string
	sequenceNr   uint64
}

func (e *cipherMessage) Encode(c cipher.AEAD, s *cipherStream) (map[string]interface{}, error) {
	plain, err := json.Marshal(e.payload)
	if err != nil {
		return nil, err
	}
	encr := s.Encrypt(c, plain)
	return map[string]interface{}{
		"mangledTypeName": "RemotePairing.ControlChannelMessageEnvelope",
		"value": map[string]interface{}{
			"message": map[string]interface{}{
				"streamEncrypted": map[string]interface{}{
					"_0": encr,
				},
			},
			"originatedBy":   e.originatedBy,
			"sequenceNumber": e.sequenceNr,
		},
	}, nil
}

func (e *cipherMessage) Decode(c cipher.AEAD, s *cipherStream, m map[string]interface{}) error {
	streamEncr, err := getChildMap(m, "value", "message", "streamEncrypted")
	if err != nil {
		return err
	}
	cph := streamEncr["_0"].([]byte)
	plain, err := s.Decrypt(c, cph)
	if err != nil {
		return err
	}
	res := make(map[string]interface{})
	err = json.Unmarshal(plain, &res)
	if err != nil {
		return err
	}
	e.payload = res
	return nil
}

type TunnelInfo struct {
	PrivateKey      *rsa.PrivateKey
	DevicePublicKey interface{}
	TunnelPort      uint64
}

func ConnectToTunnel(info TunnelInfo, addr string) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		//KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		//BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &info.PrivateKey.PublicKey, info.PrivateKey)
	if err != nil {
		panic(err)
	}
	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(info.PrivateKey),
		},
	)
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	cert5, err := tls.X509KeyPair(certPem, privateKeyPem)
	conf := &tls.Config{
		// We always trust whatever the phone sends, I do not see an issue here as probably
		// nobody would build a fake iphone to hack this library.
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cert5},
		ClientAuth:         tls.NoClientCert,
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("[%s]:%d", addr, info.TunnelPort), conf)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
}
