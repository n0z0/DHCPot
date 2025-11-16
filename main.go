package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

// Struktur data untuk menyimpan status lease
type Lease struct {
	IP         net.IP
	MAC        net.HardwareAddr
	ExpiryTime time.Time
	Hostname   string
}

// Server DHCP kita
type DHCPServer struct {
	serverIP      net.IP            // IP dari server DHCP ini
	subnetMask    net.IPMask        // Subnet mask
	routerIP      net.IP            // IP Gateway
	dnsServerIPs  []net.IP          // DNS Server
	ipPool        []net.IP          // Pool IP yang tersedia
	leaseDuration time.Duration     // Durasi lease
	leases        map[string]*Lease // Map untuk menyimpan lease yang aktif, key adalah MAC address string
	mu            sync.Mutex        // Mutex untuk keamanan akses konkuren
}

// Fungsi helper untuk melakukan increment pada IP address
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	return next
}

// Fungsi untuk membuat server DHCP baru
func NewDHCPServer(ifaceName, serverIPStr, subnetMaskStr, routerIPStr string, ipPoolStartStr, ipPoolEndStr string) (*DHCPServer, error) {
	serverIP := net.ParseIP(serverIPStr)
	if serverIP == nil {
		return nil, fmt.Errorf("invalid server IP address: %s", serverIPStr)
	}

	_, subnetMask, err := net.ParseCIDR(subnetMaskStr)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet mask: %s", subnetMaskStr)
	}

	routerIP := net.ParseIP(routerIPStr)
	if routerIP == nil {
		return nil, fmt.Errorf("invalid router IP address: %s", routerIPStr)
	}

	// Buat pool IP
	startIP := net.ParseIP(ipPoolStartStr)
	endIP := net.ParseIP(ipPoolEndStr)
	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP pool range")
	}

	var ipPool []net.IP
	// Perbaikan: Gunakan bytes.Compare untuk membandingkan IP dan loop hingga endIP
	for ip := startIP; bytes.Compare(ip.To4(), endIP.To4()) <= 0; ip = nextIP(ip) {
		// Tambahkan IP ke pool jika bukan IP server
		if !ip.Equal(serverIP) {
			// Salin IP untuk menghindasi masalah referensi
			ipToAdd := make(net.IP, len(ip))
			copy(ipToAdd, ip)
			ipPool = append(ipPool, ipToAdd)
		}
	}

	return &DHCPServer{
		serverIP:      serverIP,
		subnetMask:    subnetMask.Mask,
		routerIP:      routerIP,
		dnsServerIPs:  []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}, // Contoh DNS Google
		ipPool:        ipPool,
		leaseDuration: 24 * time.Hour, // Lease selama 24 jam
		leases:        make(map[string]*Lease),
	}, nil
}

// Handler utama untuk setiap paket DHCP yang diterima.
// Tanda tangan ini sudah sesuai dengan yang diharapkan oleh server4.Handler.
func (s *DHCPServer) handleDHCPRequest(conn net.PacketConn, peer net.Addr, pkt *dhcpv4.DHCPv4) {
	s.mu.Lock()
	defer s.mu.Unlock()

	macStr := pkt.ClientHWAddr.String()
	log.Printf("Received DHCP message from %s (%s), type: %v", macStr, peer, pkt.MessageType())

	switch pkt.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.handleDiscover(pkt, macStr, conn, peer)
	case dhcpv4.MessageTypeRequest:
		s.handleRequest(pkt, macStr, conn, peer)
	case dhcpv4.MessageTypeRelease:
		s.handleRelease(pkt, macStr)
	default:
		log.Printf("Ignoring message type: %v", pkt.MessageType())
	}
}

func (s *DHCPServer) handleDiscover(pkt *dhcpv4.DHCPv4, macStr string, conn net.PacketConn, peer net.Addr) {
	// Cek apakah client sudah memiliki lease
	if lease, exists := s.leases[macStr]; exists && lease.ExpiryTime.After(time.Now()) {
		log.Printf("Client %s already has a lease for %s", macStr, lease.IP)
		s.sendOffer(pkt, lease.IP, conn, peer)
		return
	}

	// Cari IP yang tersedia dari pool
	ip := s.findAvailableIP()
	if ip == nil {
		log.Printf("No available IP in the pool for %s", macStr)
		return
	}

	log.Printf("Offering IP %s to %s", ip, macStr)
	s.sendOffer(pkt, ip, conn, peer)
}

func (s *DHCPServer) handleRequest(pkt *dhcpv4.DHCPv4, macStr string, conn net.PacketConn, peer net.Addr) {
	requestedIP := pkt.RequestedIPAddress()

	// Verifikasi IP yang diminta valid dan tersedia
	if !s.isIPInPool(requestedIP) {
		log.Printf("Client %s requested invalid IP %s", macStr, requestedIP)
		s.sendNak(pkt, conn, peer)
		return
	}

	// Jika client sudah memiliki lease, perbarui
	if lease, exists := s.leases[macStr]; exists && lease.IP.Equal(requestedIP) {
		lease.ExpiryTime = time.Now().Add(s.leaseDuration)
		log.Printf("ACK: Renewed lease for %s -> %s", macStr, requestedIP)
		s.sendAck(pkt, requestedIP, conn, peer)
		return
	}

	// Jika IP tersedia, berikan lease baru
	if s.isIPAvailable(requestedIP) {
		s.leases[macStr] = &Lease{
			IP:         requestedIP,
			MAC:        pkt.ClientHWAddr,
			ExpiryTime: time.Now().Add(s.leaseDuration),
			Hostname:   pkt.HostName(),
		}
		log.Printf("ACK: Assigned new lease for %s -> %s", macStr, requestedIP)
		s.sendAck(pkt, requestedIP, conn, peer)
		return
	}

	log.Printf("NAK: IP %s is not available for %s", requestedIP, macStr)
	s.sendNak(pkt, conn, peer)
}

func (s *DHCPServer) handleRelease(pkt *dhcpv4.DHCPv4, macStr string) {
	if lease, exists := s.leases[macStr]; exists {
		log.Printf("Released lease for %s -> %s", macStr, lease.IP)
		delete(s.leases, macStr)
	}
}

func (s *DHCPServer) sendOffer(pkt *dhcpv4.DHCPv4, ip net.IP, conn net.PacketConn, peer net.Addr) {
	offer, err := dhcpv4.NewReplyFromRequest(pkt,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithYourIP(ip),
		dhcpv4.WithServerIP(s.serverIP),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(s.subnetMask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(s.routerIP)),
		dhcpv4.WithOption(dhcpv4.OptDNS(s.dnsServerIPs...)),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(s.leaseDuration)),
	)
	if err != nil {
		log.Printf("Failed to build DHCPOFFER: %v", err)
		return
	}

	if _, err := conn.WriteTo(offer.ToBytes(), peer); err != nil {
		log.Printf("Failed to send DHCPOFFER: %v", err)
	}
}

func (s *DHCPServer) sendAck(pkt *dhcpv4.DHCPv4, ip net.IP, conn net.PacketConn, peer net.Addr) {
	ack, err := dhcpv4.NewReplyFromRequest(pkt,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(ip),
		dhcpv4.WithServerIP(s.serverIP),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(s.subnetMask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(s.routerIP)),
		dhcpv4.WithOption(dhcpv4.OptDNS(s.dnsServerIPs...)),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(s.leaseDuration)),
	)
	if err != nil {
		log.Printf("Failed to build DHCPACK: %v", err)
		return
	}

	if _, err := conn.WriteTo(ack.ToBytes(), peer); err != nil {
		log.Printf("Failed to send DHCPACK: %v", err)
	}
}

func (s *DHCPServer) sendNak(pkt *dhcpv4.DHCPv4, conn net.PacketConn, peer net.Addr) {
	nak, err := dhcpv4.NewReplyFromRequest(pkt,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithServerIP(s.serverIP),
		dhcpv4.WithOption(dhcpv4.OptMessage("Requested IP not available.")),
	)
	if err != nil {
		log.Printf("Failed to build DHCPNAK: %v", err)
		return
	}

	if _, err := conn.WriteTo(nak.ToBytes(), peer); err != nil {
		log.Printf("Failed to send DHCPNAK: %v", err)
	}
}

// Helper untuk mencari IP yang tersedia
func (s *DHCPServer) findAvailableIP() net.IP {
	for _, ip := range s.ipPool {
		if s.isIPAvailable(ip) {
			return ip
		}
	}
	return nil
}

func (s *DHCPServer) isIPAvailable(ip net.IP) bool {
	// Cek apakah IP sedang digunakan dalam lease aktif
	for _, lease := range s.leases {
		if lease.IP.Equal(ip) && lease.ExpiryTime.After(time.Now()) {
			return false
		}
	}
	return true
}

func (s *DHCPServer) isIPInPool(ip net.IP) bool {
	for _, poolIP := range s.ipPool {
		if poolIP.Equal(ip) {
			return true
		}
	}
	return false
}

func main() {
	// --- KONFIGURASI SERVER ---
	// Ganti nilai-nilai ini sesuai dengan jaringan Anda
	ifaceName := "eth0"            // Nama antarmuka jaringan
	serverIP := "192.168.1.10"     // IP statis dari server DHCP ini
	subnetMask := "255.255.255.0"  // Subnet mask
	routerIP := "192.168.1.1"      // IP Gateway
	ipPoolStart := "192.168.1.100" // Awal pool IP
	ipPoolEnd := "192.168.1.200"   // Akhir pool IP
	// -------------------------

	dhcpServer, err := NewDHCPServer(ifaceName, serverIP, subnetMask, routerIP, ipPoolStart, ipPoolEnd)
	if err != nil {
		log.Fatalf("Failed to create DHCP server: %v", err)
	}

	log.Printf("Starting DHCP server on interface %s", ifaceName)
	log.Printf("Server IP: %s", serverIP)
	log.Printf("IP Pool: %s - %s", ipPoolStart, ipPoolEnd)

	// Buat listener pada antarmuka jaringan
	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 67}

	// PERBAIKAN AKHIR: Buat handler yang cocok dengan tipe server4.Handler
	// dengan membungkus pemanggilan method kita ke dalam fungsi anonim.
	handler := func(conn net.PacketConn, peer net.Addr, pkt *dhcpv4.DHCPv4) {
		dhcpServer.handleDHCPRequest(conn, peer, pkt)
	}

	server, err := server4.NewServer(ifaceName, laddr, handler)
	if err != nil {
		log.Fatalf("Failed to start DHCP server listener: %v", err)
	}

	// Jalankan server
	if err := server.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
