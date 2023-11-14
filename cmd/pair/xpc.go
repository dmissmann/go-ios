package main

import (
	"github.com/danielpaulus/go-ios/ios/xpc"
	log "github.com/sirupsen/logrus"
	"io"
)

type XpcConnection struct {
	out io.ReadWriter
	in  io.ReadWriter
	c   io.Closer
}

func NewXpcConnection(h *HttpConnection) (XpcConnection, error) {
	out := NewStreamReadWriter(h, 1)
	in := NewStreamReadWriter(h, 3)

	xpc.EncodeMessage(out, xpc.Message{
		Flags: xpc.AlwaysSetFlag,
		Id:    0,
		Body:  map[string]interface{}{},
	})

	m, err := xpc.DecodeMessage(out)
	if err != nil {
		return XpcConnection{}, err
	}
	log.Printf("%v", m)

	err = xpc.EncodeMessage(in, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.InitHandshakeFlag,
		Id:    0,
	})
	if err != nil {
		return XpcConnection{}, err
	}

	m, err = xpc.DecodeMessage(in)
	if err != nil {
		return XpcConnection{}, err
	}
	log.Printf("%+v", m)

	err = xpc.EncodeMessage(out, xpc.Message{
		Flags: xpc.AlwaysSetFlag | 0x200,
		Id:    0,
	})
	if err != nil {
		return XpcConnection{}, err
	}

	m, err = xpc.DecodeMessage(out)
	if err != nil {
		return XpcConnection{}, err
	}
	return XpcConnection{
		out: out,
		in:  in,
		c:   h,
	}, nil
}
