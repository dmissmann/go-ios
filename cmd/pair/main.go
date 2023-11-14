package main

import (
	"github.com/danielpaulus/go-ios/ios/xpc"
	"log"
)

func main() {
	host := "fe80::c060:e7ff:fe19:ab61%en10"

	h, err := NewHttpConnectionWithAddr(host, 58783)
	if err != nil {
		panic(err)
	}

	id1Writer := NewStreamReadWriter(h, 1)

	xpc.EncodeMessage(id1Writer, xpc.Message{
		Flags: xpc.AlwaysSetFlag,
		Id:    0,
		Body:  map[string]interface{}{},
	})

	m, err := xpc.DecodeMessage(id1Writer)
	if err != nil {
		panic(err)
	}
	log.Printf("%+v", m)

	id3Writer := NewStreamReadWriter(h, 3)

	err = xpc.EncodeMessage(id3Writer, xpc.Message{
		Flags: xpc.AlwaysSetFlag | xpc.InitHandshakeFlag,
		Id:    0,
	})
	if err != nil {
		panic(err)
	}

	m, err = xpc.DecodeMessage(id3Writer)
	if err != nil {
		panic(err)
	}
	log.Printf("%+v", m)

	err = xpc.EncodeMessage(id1Writer, xpc.Message{
		Flags: xpc.AlwaysSetFlag | 0x200,
		Id:    0,
	})
	if err != nil {
		panic(err)
	}

	m, err = xpc.DecodeMessage(id1Writer)
	if err != nil {
		panic(err)
	}
	log.Printf("%+v", m)

	rsd := NewRsdConnection(h)

	ha, err := rsd.Handshake()
	if err != nil {
		panic(err)
	}
	log.Printf("%+v", ha.Services)

	//hb, _ := base64.StdEncoding.DecodeString("kguwKQEBAQBQAAAAAAAAAAMAAAAAAAAAQjcTQgUAAAAA8AAAQAAAAAIAAABNZXNzYWdlVHlwZQAAkAAACgAAAEhlYXJ0YmVhdAAAAFNlcXVlbmNlTnVtYmVyAAAAQAAAAQAAAAAAAAAAAGgAAAAAAAGSC7ApAQEBAFAAAAAAAAAABQAAAAAAAABCNxNCBQAAAADwAABAAAAAAgAAAE1lc3NhZ2VUeXBlAACQAAAKAAAASGVhcnRiZWF0AAAAU2VxdWVuY2VOdW1iZXIAAABAAAACAAAAAAAAAAAAaAAAAAAAAZILsCkBAQEAUAAAAAAAAAAHAAAAAAAAAEI3E0IFAAAAAPAAAEAAAAACAAAATWVzc2FnZVR5cGUAAJAAAAoAAABIZWFydGJlYXQAAABTZXF1ZW5jZU51bWJlcgAAAEAAAAMAAAAAAAAAAABoAAAAAAABkguwKQEBAQBQAAAAAAAAAAkAAAAAAAAAQjcTQgUAAAAA8AAAQAAAAAIAAABNZXNzYWdlVHlwZQAAkAAACgAAAEhlYXJ0YmVhdAAAAFNlcXVlbmNlTnVtYmVyAAAAQAAABAAAAAAAAAAAAGgAAAAAAAGSC7ApAQEBAFAAAAAAAAAACwAAAAAAAABCNxNCBQAAAADwAABAAAAAAgAAAE1lc3NhZ2VUeXBlAACQAAAKAAAASGVhcnRiZWF0AAAAU2VxdWVuY2VOdW1iZXIAAABAAAAFAAAAAAAAAA==")
	//h.WriteClientServerStream(hb)
	//
	//for i := uint64(1); i <= 5; i++ {
	//	err := rsd.SendHeartbeat(i)
	//	if err != nil {
	//		log.Printf("%s", err.Error())
	//		break
	//	}
	//}

	h.Close()

	tunnelPort := ha.Services["com.apple.internal.dt.coredevice.untrusted.tunnelservice"].Port

	tunnel, err := NewTunnelService(host, tunnelPort)
	if err != nil {
		panic(err)
	}
	defer tunnel.Close()

	err = tunnel.Pair()
	if err != nil {
		panic(err)
	}
	info, err := tunnel.CreateTunnelListener()
	if err != nil {
		log.Printf("lets panic")
		panic(err)
	}

	//tunnel.Close()

	ConnectToTunnel(info, host)
	log.Printf("connected to tunnel service")
	//err = xpc.EncodeMessage(id1Writer, xpc.Message{
	//	Flags: xpc.AlwaysSetFlag | xpc.DataFlag,
	//	Id:    0,
	//	Body:  createHandshakeRequestMessage(),
	//})
	//if err != nil {
	//	panic(err)
	//}
	//
	//m, err = xpc.DecodeMessage(id1Writer)
	//if err != nil {
	//	panic(err)
	//}
	//log.Printf("%+v", m)
}
