package main

import (
	"net"
)

func main() {
	ln, err := net.Listen("tcp", "0.0.0.0:1989")
	if err != nil {
		println(err)
	}
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			println("listen accept error %v\n", err)
			break
		}
		println("client address: ", clientConn.RemoteAddr())
		go HandleProxyConn(clientConn)
	}
}
