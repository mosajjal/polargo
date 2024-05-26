package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/lqqyt2423/go-mitmproxy/proxy"
)

type PcapOverIP struct {
	proxy.BaseAddon
	destination string // IP:port of pcap-over-ip server
	dst         io.Writer
}

func getIPPort(addr net.Addr) (net.IP, uint16) {
	host, port, _ := net.SplitHostPort(addr.String())
	ip := net.ParseIP(host)
	portInt, _ := strconv.Atoi(port)
	return ip, uint16(portInt)

}

func (p *PcapOverIP) Response(f *proxy.Flow) {
	// TCP METHOD - maintaining the connection
	// if p.dst == nil {
	// 	addrPort, err := netip.ParseAddrPort(p.destination)
	// 	if err != nil {
	// 		log.Println(err)
	// 		return
	// 	}
	// 	if dstConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IP(addrPort.Addr().AsSlice()), Port: int(addrPort.Port())}); err != nil {
	// 		log.Println(err)
	// 		return
	// 	} else {
	// 		// defer dstConn.Close()
	// 		dstConn.SetKeepAlive(true)

	// 		// create a virtual bufio writer to write to the dstConn
	// 		buf := new(bytes.Buffer)
	// 		p.dst = buf
	// 		go func() {
	// 			for {
	// 				if _, err := io.Copy(dstConn, buf); err != nil {
	// 					log.Println(err)
	// 					return
	// 				}
	// 			}
	// 		}()
	// 	}
	// }

	// TCP METHOD - reconnect
	addrPort, err := netip.ParseAddrPort(p.destination)
	if err != nil {
		log.Println(err)
		return
	}
	if dstConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IP(addrPort.Addr().AsSlice()), Port: int(addrPort.Port())}); err != nil {
		log.Println(err)
		return
	} else {
		// defer dstConn.Close()
		dstConn.SetKeepAlive(false)
		defer dstConn.Close()
		p.dst = dstConn
	}

	// FILE METHOD
	// if f, err := os.Create("./http-req-resp.pcap"); err != nil {
	// 	log.Fatal(err)
	// } else {
	// 	defer f.Close()
	// 	p.dst = f
	// }

	// create a http response object from f.Response
	resp := http.Response{
		StatusCode:    f.Response.StatusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        f.Response.Header,
		Body:          io.NopCloser(bytes.NewReader(f.Response.Body)),
		ContentLength: int64(len(f.Response.Body)),
	}

	reqBytes, respBytes, err := extractRequestResponse(f.Request.Raw(), &resp)
	if err != nil {
		log.Println(err)
		return
	}

	srcIP, srcPort := getIPPort(f.ConnContext.ClientConn.Conn.RemoteAddr())
	dstIP, dstPort := getIPPort(f.ConnContext.ServerConn.Conn.RemoteAddr())

	// Write the request and response bytes to a pcap file
	if err := writePcap(reqBytes, respBytes, srcIP, dstIP, srcPort, dstPort, p.dst); err != nil {
		log.Println(err)
	}
	log.Printf("Wrote pcap file for %s:%d -> %s:%d. size: %d\n", srcIP, srcPort, dstIP, dstPort, len(reqBytes)+len(respBytes))

}

var (
	listen      = flag.String("listen", ":9080", "listen address")
	destination = flag.String("destination", "127.0.0.1:1234", "destination pcap-over-ip address")
)

func main() {
	flag.Parse()

	opts := &proxy.Options{
		Addr:              *listen,
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	p.AddAddon(&PcapOverIP{
		destination: *destination,
	})

	log.Fatal(p.Start())
}
