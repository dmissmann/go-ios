package main

import (
	"bytes"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"log"
	"net"
	"time"
)

type HttpConnection struct {
	f                  *http2.Framer
	clientServerStream *bytes.Buffer
	serverClientStream *bytes.Buffer
	c                  io.Closer
}

func (r *HttpConnection) Close() error {
	log.Printf("close http connection")
	return r.c.Close()
}

func NewHttpConnectionWithAddr(host string, port uint32) (*HttpConnection, error) {
	addr, err := net.ResolveTCPAddr("tcp6", fmt.Sprintf("[%s]:%d", host, port))
	if err != nil {
		return nil, err
	}

	//raddr, err := net.ResolveTCPAddr("tcp6", fmt.Sprintf("[%s]:0", "fe80::c060:e7ff:fe19:ab9e"))

	conn, err := net.DialTCP("tcp", nil, addr)

	if err != nil {
		return nil, err
	}

	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(1 * time.Second)
	return NewHttpConnection(conn)
}

func NewHttpConnection(rw io.ReadWriteCloser) (*HttpConnection, error) {
	framer := http2.NewFramer(rw, rw)

	_, err := rw.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if err != nil {
		return nil, err
	}

	err = framer.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 10485776},
	)

	err = framer.WriteWindowUpdate(0, 983041)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	err = framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:   1,
		EndHeaders: true,
	})
	if err != nil {
		return nil, err
	}

	err = framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:   3,
		EndHeaders: true,
	})
	if err != nil {
		return nil, err
	}

	return &HttpConnection{
		f:                  framer,
		clientServerStream: bytes.NewBuffer(nil),
		serverClientStream: bytes.NewBuffer(nil),
		c:                  rw,
	}, nil
}

func (r *HttpConnection) ReadClientServerStream(p []byte) (int, error) {
	for r.clientServerStream.Len() < len(p) {
		err := r.readDataFrame()
		if err != nil {
			return 0, err
		}
	}
	return r.clientServerStream.Read(p)
}

func (r *HttpConnection) WriteClientServerStream(p []byte) (int, error) {
	return r.Write(p, 1)
}

func (r *HttpConnection) WriteServerClientStream(p []byte) (int, error) {
	return r.Write(p, 3)
}

func (r *HttpConnection) Write(p []byte, streamId uint32) (int, error) {
	err := r.f.WriteData(streamId, false, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (r *HttpConnection) readDataFrame() error {
	for {
		f, err := r.f.ReadFrame()
		if err != nil {
			return err
		}
		log.Printf("received frame %s(%d)", f.Header().Type.String(), f.Header().StreamID)
		switch f.Header().Type {
		case http2.FrameData:
			d := f.(*http2.DataFrame)
			switch d.StreamID {
			case 1:
				r.clientServerStream.Write(d.Data())
			case 3:
				r.serverClientStream.Write(d.Data())
			default:
				panic(fmt.Errorf("unknown stream id %d", d.StreamID))
			}
			return nil
		case http2.FrameGoAway:
			return fmt.Errorf("received GOAWAY")
		default:
			break
		}
	}
}

func (r *HttpConnection) ReadServerClientStream(p []byte) (int, error) {
	for r.serverClientStream.Len() < len(p) {
		err := r.readDataFrame()
		if err != nil {
			return 0, err
		}
	}
	return r.serverClientStream.Read(p)
}

type HttpStreamReadWriter struct {
	h        *HttpConnection
	streamId uint32
}

func NewStreamReadWriter(h *HttpConnection, streamId uint32) HttpStreamReadWriter {
	return HttpStreamReadWriter{
		h:        h,
		streamId: streamId,
	}
}

func (h HttpStreamReadWriter) Read(p []byte) (n int, err error) {
	if h.streamId == 1 {
		return h.h.ReadClientServerStream(p)
	} else if h.streamId == 3 {
		return h.h.ReadServerClientStream(p)
	}
	panic(nil)
}

func (h HttpStreamReadWriter) Write(p []byte) (n int, err error) {
	if h.streamId == 1 {
		return h.h.WriteClientServerStream(p)
	} else if h.streamId == 3 {
		return h.h.WriteServerClientStream(p)
	}
	panic("implement me")
}
