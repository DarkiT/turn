package turn

import (
	"net"
	"strconv"
)

type RelayAddressGeneratorNone struct{}

func (r *RelayAddressGeneratorNone) Validate() error {
	return nil
}

func (r *RelayAddressGeneratorNone) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	conn, err := net.ListenPacket("udp", ":"+strconv.Itoa(requestedPort))
	if err != nil {
		return nil, nil, err
	}

	return conn, conn.LocalAddr(), nil
}

func (r *RelayAddressGeneratorNone) AllocateConn(network string, requestedPort int) (net.Conn, net.Addr, error) {
	listener, err := net.Listen(network, ":"+strconv.Itoa(requestedPort))
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()

	// 接受一个连接
	conn, err := listener.Accept()
	if err != nil {
		return nil, nil, err
	}
	return conn, conn.LocalAddr(), nil
}
