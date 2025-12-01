# DHCPot

DHCP rOgue Threat

| Nama Serangan | Tujuan Utama | Cara Kerja |
| :--- | :--- | :--- |
| **Rogue DHCP Server** | **Man-in-the-Middle / Phishing** | Memasang server DHCP baru untuk memberikan konfigurasi jahat. |
| **DHCP Starvation** | **Denial of Service** | "Menghabiskan" semua alamat IP yang tersedia di server DHCP resmi. Penyerang meminta IP secara berulang-ulang menggunakan MAC address palsu. Akibatnya, klien baru tidak bisa mendapatkan IP. Serangan ini kadang dilakukan *sebelum* melakukan Rogue DHCP agar klien terpaksa menggunakan server nakal. |
