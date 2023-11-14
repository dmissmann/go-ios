package main

import (
	"fmt"
	"github.com/grandcat/zeroconf"
	"log"
	"net"
	"time"

	"context"
)

func main() {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatalln("Failed to initialize resolver:", err.Error())
	}

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			log.Println(entry)
			ip := entry.AddrIPv6[0]
			t, err := net.ResolveTCPAddr("tcp6", fmt.Sprintf("[%s]:0", ip.String()))
			if err != nil {
				panic(err)
			}
			log.Printf("%s\n", t.Network())
			c, err := net.Dial("tcp6", fmt.Sprintf("[%s%%%s]:%d", ip.String(), "en10", entry.Port))

			if err != nil {
				panic(err)
			}
			defer c.Close()
		}
		log.Println("No more entries.")
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	err = resolver.Browse(ctx, "_remoted._tcp", "local.", entries)
	if err != nil {
		log.Fatalln("Failed to browse:", err.Error())
	}

	<-ctx.Done()
}
