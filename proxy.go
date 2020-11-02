package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

func httpLogf(format string, v ...interface{}) {
	log.Printf("[http] "+format, v...)
}

func socks4Logf(format string, v ...interface{}) {
	log.Printf("[socks4] "+format, v...)
}

func socks5Logf(format string, v ...interface{}) {
	log.Printf("[socks5] "+format, v...)
}

func getHostPortType(line []byte) (host, port, tp string, err error) {
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	slc := strings.Split(string(line), " ")
	if len(slc) < 2 {
		err = fmt.Errorf("first line err %v", string(line))
		return
	}
	switch slc[0] {
	case "CONNECT":
		hp := strings.Split(slc[1], ":")
		if len(hp) != 2 {
			err = fmt.Errorf("connect extract host,port err %v", slc[1])
			return
		}
		host, port, tp = hp[0], hp[1], "https"
	default:
		thp := strings.Split(slc[1], "/")
		if len(thp) < 3 {
			err = fmt.Errorf("%v host err %v", slc[0], slc[1])
			return
		}
		hp := strings.Split(thp[2], ":")
		if len(hp) == 1 {
			host, port, tp = hp[0], "80", "http"
		} else if len(hp) == 2 {
			host, port, tp = hp[0], hp[1], "http"
		} else {
			err = fmt.Errorf("%v extract host,port err %v", slc[0], slc[1])
			return
		}
	}
	return
}

func HandleHttp(clientConn net.Conn, v byte) (err error) {
	err = nil

	data := make([]byte, 4096)
	n := 1
	data[0] = v
	bts := make([]byte, 1)
	for {
		_, err := clientConn.Read(bts)
		if err != nil {
			break
		} else {
			data[n] = bts[0]
			n++
			if bts[0] == '\n' {
				break
			}
		}
	}

	// log.Println(string(data[0:n]))
	hosts, ports, tps, err := getHostPortType(data[0:n])
	if err != nil {
		fmt.Printf("get host,port,type error %v", err)
		return
	}

	// var remoteConn net.Conn
	// remoteConn, err = net.Dial("tcp", hosts+":"+ports)
	remoteConn, err := net.DialTimeout("tcp", hosts+":"+ports, time.Duration(10)*time.Second)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer remoteConn.Close()
	// remoteConn.SetDeadline(time.Duration(10) * time.Second)
	if tps == "https" {
		clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		var last byte
		for {
			_, err := clientConn.Read(bts)
			if err != nil {
				break
			} else if bts[0] == '\r' {
				continue
			} else if bts[0] == '\n' {
				if last == '\n' {
					break
				}
			}
			last = bts[0]
		}
	} else {
		remoteConn.Write(data[0:n])
	}
	go io.Copy(clientConn, remoteConn)
	io.Copy(remoteConn, clientConn)

	return
}

// socks5
const (
	Version byte = 0x05

	MethodNoAuth byte = 0x00
	MethodAuth   byte = 0x02
	MethodNone   byte = 0xFF

	CmdConnect      byte = 0x01
	CmdUdpAssociate byte = 0x03

	ATYPIPv4   byte = 0x01
	ATYPDomain byte = 0x03
	ATYPIPv6   byte = 0x04
)

func getAddr(conn net.Conn) (atyp, cmd byte, addrBytes []byte, port int, data []byte, err error) {
	var ver byte
	buf := make([]byte, 1024)
	// n, err := conn.Read(buf[:4])
	// if buf, er := p.readBuf(conn, 4); er != nil {
	conn.SetReadDeadline(time.Now().Add(time.Second * 6))
	n, er := conn.Read(buf[:])
	if er != nil {
		err = er
		data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	} else {
		fmt.Println(n, buf[:n])
		ver = buf[0]
		cmd = buf[1]
		atyp = buf[3]
	}

	if ver != Version {
		err = errors.New("unsupported socks version")
		data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	}
	if bytes.IndexByte([]byte{CmdConnect, CmdUdpAssociate}, cmd) == -1 {
		err = errors.New("unsupported CMD")
		data = []byte{Version, 0x07, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	}
	// n := 0
	switch atyp {
	case ATYPIPv4:
		// addrBytes, err = p.readBuf(conn, 4)
		// conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		// _, err = conn.Read(buf[:4])
		addrBytes = buf[4 : 4+4]
		if err != nil {
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
	case ATYPDomain:
		var domainLen int
		// if buf, er := p.readBuf(conn, 1); er != nil {
		// conn.SetReadDeadline(time.Now().Add(time.Second * 5))

		// n, _ := conn.Read(buf[:])
		// fmt.Println(n, buf[:n])

		// if _, er := conn.Read(buf[:1]); er != nil {
		// 	err = er
		// 	data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		// 	return
		// } else {
		// 	domainLen = int(buf[0])
		// }
		domainLen = int(buf[4])
		if domainLen <= 0 {
			err = errors.New("length of domain is zero")
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
		println("domainLen", domainLen)
		// addrBytes, err = p.readBuf(conn, domainLen)
		// conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		// n, err = conn.Read(buf[:domainLen])
		addrBytes = buf[5 : 5+domainLen]
		// fmt.Println(n, addrBytes)
		if err != nil {
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
	case ATYPIPv6:
		// addrBytes, err = p.readBuf(conn, 16)
		// conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		// n, err = conn.Read(buf[:16])
		addrBytes = buf[4 : 4+16]
		if err != nil {
			data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			return
		}
	default:
		err = errors.New("unsupported ATYP")
		data = []byte{Version, 0x08, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return
	}

	// if buf, er := p.readBuf(conn, 2); er != nil {
	// conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	// if _, er := conn.Read(buf[:2]); er != nil {
	// 	err = er
	// 	data = []byte{Version, 0x05, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// 	return
	// } else {
	// 	port = int(binary.BigEndian.Uint16(buf))
	// }
	// fmt.Println(buf[:2], addrBytes)
	port = int(binary.BigEndian.Uint16(buf[n-2 : n]))
	fmt.Println(buf[n-2:n], port)
	return
}

func HandleSocks5(ClientConn net.Conn) (err error) {
	err = nil
	data := make([]byte, 1024)
	// reply := []byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x22, 0x22}

	//version
	n, err := ClientConn.Read(data[:])
	fmt.Println(n, data[:n])
	// methodLen := int(data[1])
	_, err = ClientConn.Write([]byte{Version, MethodNoAuth})

	//addr
	atyp, cmd, addrBytes, port, data, err := getAddr(ClientConn)
	if err != nil {
		_, err = ClientConn.Write(data)
		return err
	} else {
		fmt.Println(cmd, atyp, port, addrBytes)
	}
	var ip net.IP
	switch atyp {
	case ATYPIPv4:
		ip = net.IPv4(addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
		socks5Logf(string(ip))
	case ATYPIPv6:
		ip = net.ParseIP(string(addrBytes))
		socks5Logf(string(ip))
	case ATYPDomain:
		domain := string(addrBytes)
		socks5Logf(domain)
		if addr, er := net.ResolveIPAddr("ip", domain); er != nil {
			_, err = ClientConn.Write([]byte{Version, 0x04, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return err
		} else {
			ip = addr.IP
			fmt.Println(domain, addr.IP)
		}
	}
	// p.port = port
	//check remote addr
	switch cmd {
	case CmdConnect:
		if !ip.IsGlobalUnicast() || port <= 0 {
			ClientConn.Write([]byte{Version, 0x02, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return errors.New("remote address error")
		}
		println("tcp")
		RemoteConn, err := net.DialTimeout("tcp", ip.String()+":"+strconv.Itoa(port), time.Second*time.Duration(10))
		if err != nil {
			_, _ = ClientConn.Write([]byte{Version, 0x04, 0x00, ATYPIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			return err
		}

		bindIP := ClientConn.LocalAddr().(*net.TCPAddr).IP
		res := make([]byte, 0, 22)
		if ip := bindIP.To4(); ip != nil {
			//IPv4, len is 4
			res = append(res, []byte{Version, 0x00, 0x00, ATYPIPv4}...)
			res = append(res, ip...)
		} else {
			//IPv6, len is 16
			res = append(res, []byte{Version, 0x00, 0x00, ATYPIPv6}...)
			res = append(res, bindIP...)
		}

		portByte := [2]byte{}
		binary.BigEndian.PutUint16(portByte[:], uint16(ClientConn.LocalAddr().(*net.TCPAddr).Port))
		res = append(res, portByte[:]...)
		if _, err := ClientConn.Write(res); err != nil {
			return err
		}
		defer RemoteConn.Close()

		go io.Copy(RemoteConn, ClientConn)
		io.Copy(ClientConn, RemoteConn)

	case CmdUdpAssociate:
		//udp
		println("udp")

	}

	return
}

func HandleSocks4(clientConn net.Conn) (err error) {
	err = nil
	var body [128]byte
	_, err = clientConn.Read(body[:])
	if err != nil {
		return
	}
	reply := make([]byte, 8)
	if body[0] != 0x01 { //socks4Connect
		reply[1] = 0x5B //socks4Rejected
		clientConn.Write(reply)
		return
	}
	host := net.IPv4(body[3], body[4], body[5], body[6]).String()
	port := strconv.Itoa(int(body[1])<<8 | int(body[2]))
	remoteConn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		reply[1] = 0x5C //socks4ConnectFailed
		clientConn.Write(reply)
		return
	}
	defer remoteConn.Close()
	// clientConn.Write([]byte{0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	reply[1] = 0x5A //socks4Granted
	if _, err = clientConn.Write(reply); err != nil {
		return
	}
	go func() {
		io.Copy(clientConn, remoteConn)
		// clientConn.Close()
		// remoteConn.Close()
	}()
	io.Copy(remoteConn, clientConn)
	// clientConn.Close()
	// remoteConn.Close()
	return
}

func HandleProxyConn(clientConn net.Conn) {
	defer clientConn.Close()
	v := make([]byte, 1)
	clientConn.Read(v)
	// reqBufReader := bufio.NewReader(clientConn)
	// v, err := reqBufReader.Peek(1)
	if v[0] == 0x04 {
		log.Println("HandleSocks4")
		err := HandleSocks4(clientConn)
		if err != nil {
			log.Println(err)
			return
		}
	} else if v[0] == 0x05 {
		log.Println("HandleSocks5")
		err := HandleSocks5(clientConn)
		if err != nil {
			log.Println(err)
			return
		}
	} else if v[0] >= 'A' && v[0] <= 'Z' {
		log.Println("HandleHttp", v[0], string(v[0]))

		err := HandleHttp(clientConn, v[0])
		if err != nil {
			log.Println(err)
		}
		return
	} else {
		log.Println("unsupported socks version")
		return
	}
	return

}
