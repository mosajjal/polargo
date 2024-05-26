package main

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func extractRequestResponse(req *http.Request, resp *http.Response) ([]byte, []byte, error) {
	// Extract the request
	var reqBuffer bytes.Buffer
	if err := req.Write(&reqBuffer); err != nil {
		return nil, nil, err
	}
	reqBytes := reqBuffer.Bytes()

	// Extract the response
	var respBuffer bytes.Buffer
	if err := resp.Write(&respBuffer); err != nil {
		return nil, nil, err
	}
	respBytes := respBuffer.Bytes()

	return reqBytes, respBytes, nil
}

func writePcap(reqBytes, respBytes []byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, destination io.Writer) error {

	w := pcapgo.NewWriter(destination)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err
	}

	// Ethernet layer
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
		Length:       0, // will be filled in for us
	}

	// IP layer
	ipLayerSrc := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	ipLayerDst := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    dstIP,
		DstIP:    srcIP,
		Protocol: layers.IPProtocolTCP,
	}

	// TCP layer for the request
	tcpLayerReq := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		SYN:        true,
		Ack:        0,
		Seq:        rand.Uint32(),
		DataOffset: 5, // Assuming no options, the TCP header size is 5 (in 32-bit words)
		Window:     14600,
	}

	// TCP layer for the response
	tcpLayerResp := &layers.TCP{
		SrcPort:    layers.TCPPort(dstPort),
		DstPort:    layers.TCPPort(srcPort),
		SYN:        true,
		Ack:        0,
		Seq:        rand.Uint32(),
		DataOffset: 5, // Assuming no options, the TCP header size is 5 (in 32-bit words)
		Window:     14600,
	}

	// Assuming ipLayerReq is your IP layer for the request
	tcpLayerReq.SetNetworkLayerForChecksum(ipLayerSrc)

	// Assuming ipLayerResp is your IP layer for the response
	tcpLayerResp.SetNetworkLayerForChecksum(ipLayerDst)

	// Serialize layers and payload
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// TODO: write a dummy tcp 3-way handshake
	// SYN
	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerSrc, tcpLayerReq); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// synack
	tcpLayerResp.SYN = true
	tcpLayerResp.ACK = true
	tcpLayerResp.Ack = tcpLayerReq.Seq + 1
	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerDst, tcpLayerResp); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// ack
	tcpLayerReq.SYN = false
	tcpLayerReq.ACK = true
	tcpLayerReq.Seq++
	tcpLayerReq.Ack = tcpLayerResp.Seq + 1

	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerSrc, tcpLayerReq); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// Serialize the request packet
	buf = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerSrc, tcpLayerReq, gopacket.Payload(reqBytes)); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		tcpLayerReq.Seq += uint32(len(reqBytes))
		tcpLayerReq.PSH = true
		// Write the request packet to pcap
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// fake ack for the request
	buf = gopacket.NewSerializeBuffer()
	tcpLayerResp.ACK = true
	tcpLayerResp.SYN = false
	tcpLayerResp.Seq = tcpLayerReq.Ack
	tcpLayerResp.Ack = tcpLayerReq.Seq
	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerDst, tcpLayerResp); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// Serialize the response packet
	buf = gopacket.NewSerializeBuffer()
	tcpLayerResp.PSH = true
	tcpLayerResp.ACK = true
	tcpLayerResp.Seq = tcpLayerReq.Ack
	tcpLayerResp.Ack = tcpLayerReq.Seq
	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerDst, tcpLayerResp, gopacket.Payload(respBytes)); err != nil {
		return err
	} else {
		incomingPacket := buf.Bytes()

		// Write the response packet to pcap
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(incomingPacket),
			Length:        len(incomingPacket),
		}, incomingPacket); err != nil {
			return err
		}
	}

	// send a dummy ack for the response
	tcpLayerReq.PSH = false
	tcpLayerReq.ACK = true
	tcpLayerReq.SYN = false
	tcpLayerReq.Seq = tcpLayerResp.Ack
	tcpLayerReq.Ack = tcpLayerResp.Seq + uint32(len(respBytes))
	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerSrc, tcpLayerReq); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// Finack from the source
	tcpLayerReq.FIN = true
	tcpLayerReq.ACK = true

	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerSrc, tcpLayerReq); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// Finack from the destination
	tcpLayerResp.FIN = true
	tcpLayerResp.ACK = true
	tcpLayerResp.PSH = false
	tcpLayerResp.Seq = tcpLayerReq.Ack
	tcpLayerResp.Ack = tcpLayerReq.Seq + 1

	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerDst, tcpLayerResp); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	// final ack from the source
	tcpLayerReq.FIN = false
	tcpLayerReq.ACK = true
	tcpLayerReq.Seq++
	tcpLayerReq.Ack = tcpLayerResp.Seq + 1

	if err := gopacket.SerializeLayers(buf, opts, ethernetLayer, ipLayerSrc, tcpLayerReq); err != nil {
		return err
	} else {
		outgoingPacket := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(outgoingPacket),
			Length:        len(outgoingPacket),
		}, outgoingPacket); err != nil {
			return err
		}
	}

	return nil
}
