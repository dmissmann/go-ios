package main

import (
	"crypto/sha512"
	"fmt"
	"github.com/tadglines/go-pkgs/crypto/srp"
)

type SrpInfo struct {
	ClientPublic []byte
	ClientProof  []byte
	Salt         []byte
	SessionKey   []byte
	c            *srp.ClientSession
}

func New(salt, publicKey []byte) ([]byte, []byte, error) {
	//s, err := srp.NewWithHash(crypto.SHA1, 3072)
	//if err != nil {
	//	return nil, nil, err
	//}
	//c, err := s.NewClient([]byte("Pair-Setup"), []byte("000000"))
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//srv := fmt.Sprintf("%s:%s", hex.EncodeToString(salt), hex.EncodeToString(publicKey))
	//creds := c.Credentials()
	//if err != nil {
	//	return nil, nil, err
	//}
	//log.Printf("%s", creds)
	//
	//p, err := c.Generate(srv)
	//if err != nil {
	//	return nil, nil, err
	//}
	//decodeString, err := hex.DecodeString(p)
	//clientPublic, err := hex.DecodeString(strings.Split(creds, ":")[1])
	//return decodeString, clientPublic, err
	s, err := srp.NewSRP("rfc5054.3072", sha512.New, func(salt, password []byte) []byte {
		h1 := sha512.New()
		h2 := sha512.New()
		h2.Write([]byte(fmt.Sprintf("%s:%s", "Pair-Setup", string(password))))
		h1.Write(salt)
		h1.Write(h2.Sum(nil))
		return h1.Sum(nil)
	})
	if err != nil {
		panic(err)
	}
	c := s.NewClientSession([]byte("Pair-Setup"), []byte("000000"))
	if err != nil {
		panic(err)
	}
	_, err = c.ComputeKey(salt, publicKey)
	if err != nil {
		panic(err)
	}
	a := c.ComputeAuthenticator()
	return a, c.GetA(), nil
}

func NewSrpInfo(salt, publicKey []byte) (SrpInfo, error) {
	//s, err := srp.NewWithHash(crypto.SHA1, 3072)
	//if err != nil {
	//	return nil, nil, err
	//}
	//c, err := s.NewClient([]byte("Pair-Setup"), []byte("000000"))
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//srv := fmt.Sprintf("%s:%s", hex.EncodeToString(salt), hex.EncodeToString(publicKey))
	//creds := c.Credentials()
	//if err != nil {
	//	return nil, nil, err
	//}
	//log.Printf("%s", creds)
	//
	//p, err := c.Generate(srv)
	//if err != nil {
	//	return nil, nil, err
	//}
	//decodeString, err := hex.DecodeString(p)
	//clientPublic, err := hex.DecodeString(strings.Split(creds, ":")[1])
	//return decodeString, clientPublic, err
	s, err := srp.NewSRP("rfc5054.3072", sha512.New, func(salt, password []byte) []byte {
		h1 := sha512.New()
		h2 := sha512.New()
		h2.Write([]byte(fmt.Sprintf("%s:%s", "Pair-Setup", string(password))))
		h1.Write(salt)
		h1.Write(h2.Sum(nil))
		return h1.Sum(nil)
	})
	if err != nil {
		panic(err)
	}
	c := s.NewClientSession([]byte("Pair-Setup"), []byte("000000"))
	if err != nil {
		panic(err)
	}
	key, err := c.ComputeKey(salt, publicKey)
	if err != nil {
		panic(err)
	}
	a := c.ComputeAuthenticator()
	return SrpInfo{
		ClientPublic: c.GetA(),
		ClientProof:  a,
		Salt:         salt,
		SessionKey:   key,
		c:            c,
	}, nil
}

func (s SrpInfo) VerifyServerProof(p []byte) bool {
	return s.c.VerifyServerAuthenticator(p)
}
