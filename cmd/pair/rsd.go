package main

import (
	"fmt"
	"github.com/danielpaulus/go-ios/ios/xpc"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"io"
	"strconv"
)

type Rsd struct {
	rw io.ReadWriter
	c  io.Closer
	id uint64
}

func NewRsdConnection(connection *HttpConnection) *Rsd {
	s := NewStreamReadWriter(connection, 1)
	return &Rsd{
		rw: s,
		c:  connection,
		id: 1,
	}
}

func (r *Rsd) Close() error {
	return r.c.Close()
}

type RsdHandshakeResponse struct {
	Services map[string]Service
}

type Service struct {
	Port uint32
}

func (r *Rsd) Handshake() (RsdHandshakeResponse, error) {
	err := xpc.EncodeMessage(r.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
		Body:  createHandshakeRequestMessage(),
		Id:    r.id,
	})
	r.id += 2
	if err != nil {
		return RsdHandshakeResponse{}, fmt.Errorf("could not send handshake request. %w", err)
	}
	m, err := xpc.DecodeMessage(r.rw)
	if err != nil {
		return RsdHandshakeResponse{}, fmt.Errorf("failed to receive handshake response. %w", err)
	}
	if m.Body["MessageType"] == "Handshake" {
		servicesMap := m.Body["Services"].(map[string]interface{})
		res := make(map[string]Service)
		for s, m := range servicesMap {
			s2 := m.(map[string]interface{})["Port"].(string)
			p, err := strconv.ParseInt(s2, 10, 32)
			if err != nil {
				panic(err)
			}
			res[s] = Service{
				Port: uint32(p),
			}
		}
		return RsdHandshakeResponse{Services: res}, nil
	} else {
		return RsdHandshakeResponse{}, fmt.Errorf("unknown response")
	}
	panic(nil)
}

func (r *Rsd) SendHeartbeat(heartbeatSeq uint64) error {
	err := xpc.EncodeMessage(r.rw, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.DataFlag | xpc.HeartbeatRequestFlag,
		Body: map[string]interface{}{
			"MessageType":    "Heartbeat",
			"SequenceNumber": heartbeatSeq,
		},
		Id: r.id,
	})
	r.id += 2
	if err != nil {
		return err
	}
	res, err := xpc.DecodeMessage(r.rw)
	if err != nil {
		return err
	}
	log.Infof("%v", res)
	return nil
}

func createHandshakeRequestMessage() map[string]interface{} {
	u := uuid.New().String()
	return map[string]interface{}{
		"MessageType":              "Handshake",
		"MessagingProtocolVersion": uint64(3),
		"Properties": map[string]interface{}{
			"AppleInternal":                     false,
			"BoardId":                           uint64(8),
			"BootSessionUUID":                   "993fb5a1-a52e-4ee6-8870-01e4e5237c4a",
			"BridgeVersion":                     "21.16.365.0.0,0",
			"BuildVersion":                      "23A344",
			"CPUArchitecture":                   "arm64e",
			"CertificateProductionStatus":       true,
			"CertificateSecurityMode":           true,
			"ChipID":                            uint64(24576),
			"DeviceClass":                       "Mac",
			"DeviceColor":                       "unknown",
			"DeviceEnclosureColor":              "2",
			"DeviceSupportsLockdown":            false,
			"EffectiveProductionStatusAp":       true,
			"EffectiveProductionStatusSEP":      true,
			"EffectiveSecurityModeAp":           true,
			"EffectiveSecurityModeSEP":          true,
			"HWModel":                           "J314sAP",
			"HardwarePlatform":                  "t6000",
			"HasSEP":                            true,
			"HumanReadableProductVersionString": "14.0",
			"Image4CryptoHashMethod":            "sha2-384",
			"Image4Supported":                   true,
			"IsUIBuild":                         true,
			"IsVirtualDevice":                   false,
			"MobileDeviceMinimumVersion":        "1600",
			"ModelNumber":                       "Z15G0022T",
			"OSInstallEnvironment":              false,
			"OSVersion":                         "14.0",
			"ProductName":                       "macOS",
			"ProductType":                       "MacBookPro18,3",
			"RegionCode":                        "D",
			"RegionInfo":                        "D/A",
			"RemoteXPCVersionFlags":             uint64(72057594037927942),
			"RestoreLongVersion":                "23.1.344.0.0,0",
			"SecurityDomain":                    uint64(1),
			"SensitivePropertiesVisible":        true,
			"SerialNumber":                      "YL924VYJ9Y",
			"SigningFuse":                       true,
			"SupplementalBuildVersion":          "23A344",
			"ThinningProductType":               "MacBookPro18,3",
			"UniqueChipID":                      uint64(1249397419704350),
			"UniqueDeviceID":                    "00006000-000470520162801E",
		},
		"Services": map[string]interface{}{
			//"com.apple.osanalytics.logRelay": map[string]interface{}{
			//	"Entitlement": "com.apple.SubmitDiagInfo.tower-access",
			//	"Port":        "59209",
			//	"Properties": map[string]interface{}{
			//		"UsesRemoteXPC": true,
			//	},
			//},
			//"ssh": map[string]interface{}{
			//	"Entitlement": "AppleInternal",
			//	"Port":        "22",
			//	"Properties": map[string]interface{}{
			//		"Legacy": true,
			//	},
			//},
		},
		"UUID": u,
	}
}
