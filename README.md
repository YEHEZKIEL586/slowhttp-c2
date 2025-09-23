# 🎯 Distributed Slow HTTP C2

Sistem command and control berbasis terminal yang powerful untuk distributed slow HTTP testing dan penetration testing.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/YEHEZKIEL586/slowhttp-c2)

## ⚠️ **PERINGATAN HUKUM**

Tool ini HANYA untuk tujuan **PENDIDIKAN** dan **PENETRATION TESTING YANG DIOTORISASI**!

- ✅ Gunakan hanya pada sistem yang Anda miliki
- ✅ Dapatkan otorisasi tertulis sebelum testing
- ✅ Ikuti praktik responsible disclosure
- ❌ Penggunaan tanpa otorisasi adalah ILEGAL dan TIDAK ETIS

**Dengan menggunakan tool ini, Anda setuju untuk menggunakannya secara bertanggung jawab dan legal.**

## 🚀 **Quick Start**

### Instalasi One-Line
```bash
curl -sSL https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash
```

### Instalasi Manual
```bash
git clone https://github.com/YEHEZKIEL586/slowhttp-c2.git
cd slowhttp-c2
chmod +x install.sh
./install.sh
```

### Menjalankan Sistem C2
```bash
cd slowhttp-c2
./start.sh
```

## ✨ **Fitur Utama**

- 🖥️ **Interface Terminal** - TUI yang bersih untuk operasi mudah
- 🌐 **Multi-VPS Management** - Kontrol unlimited VPS nodes via SSH
- ⚡ **Distributed Attacks** - Koordinasi serangan dari multiple sources
- 📊 **Real-time Monitoring** - Live statistics dan status updates
- 🔒 **Komunikasi Aman** - Penyimpanan password terenkripsi
- 🎯 **Multiple Attack Types** - Slowloris, Slow POST (R.U.D.Y)
- ⏱️ **Flexible Duration** - Serangan timed atau unlimited
- 🧹 **Auto Cleanup** - Pembersihan otomatis setelah serangan
- 📋 **Session Management** - Track dan manage attack sessions

## 🎮 **Jenis Serangan**

### Slowloris (Slow Headers)
- Mengirim partial HTTP headers secara sangat lambat
- Efektif terhadap server Apache, IIS
- Bandwidth rendah, dampak tinggi

### Slow POST (R.U.D.Y)
- Mengirim POST data secara sangat lambat  
- Target form handlers dan upload endpoints
- Efektif terhadap application layers

## 📋 **Requirements**

### Sistem Lokal (C2 Server)
- Linux atau macOS
- Python 3.6+
- SSH client
- Koneksi internet

### VPS Nodes
- Linux VPS dengan akses SSH
- Root atau sudo privileges
- Python 3 (auto-install jika belum ada)
- Koneksi outbound unrestricted

## 🛠️ **Instalasi**

### Instalasi Otomatis
```bash
# Download dan jalankan installer
curl -sSL https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash

# Atau dengan wget
wget -qO- https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash
```

### Instalasi Manual
```bash
# Clone repository
git clone https://github.com/YEHEZKIEL586/slowhttp-c2.git
cd slowhttp-c2

# Jalankan installer
chmod +x install.sh
./install.sh

# Atau setup manual
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 📖 **Cara Penggunaan**

### 1. Jalankan Sistem C2
```bash
./start.sh
```

### 2. Tambahkan VPS Nodes
```
Main Menu → [1] VPS Management → [1] Add VPS
```
Masukkan detail VPS:
- IP Address: `1.2.3.4`
- Username: `root`
- Password: `password_anda`
- Location: `US-East` (opsional)

### 3. Deploy Agents
```
VPS Management → [3] Deploy Agents to All
```

### 4. Luncurkan Serangan
```
Main Menu → [2] Launch Attack
```
Konfigurasi:
- Target URL: `http://target-website.com`
- Attack Type: Slowloris atau Slow POST
- VPS Selection: Pilih nodes yang akan digunakan
- Parameters: Connections, delay, duration

### 5. Monitor Real-time
```
Main Menu → [3] Monitor Attacks
```

## 🎯 **Contoh Workflow**

```bash
# Install
curl -sSL https://raw.githubusercontent.com/YEHEZKIEL586/slowhttp-c2/main/install.sh | bash

# Jalankan C2
cd ~/slowhttp-c2
./start.sh

# Tambahkan 3 VPS nodes melalui interface
# Deploy agents ke semua VPS
# Luncurkan Slowloris attack pada target
# Monitor statistik real-time
# Stop attack ketika selesai
```

## 📊 **Screenshot Interface**

### Main Menu
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    DISTRIBUTED SLOW HTTP TESTING C2                         ║
║                           Terminal Interface                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

MAIN MENU:
[1] VPS Management
[2] Launch Attack
[3] Monitor Active Attacks
[4] Attack History
[5] Exit
```

### Real-time Monitoring
```
VPS STATUS:
IP Address      Status       Processes  Last Update
1.2.3.4         ATTACKING    2          10:30:15
5.6.7.8         ATTACKING    2          10:30:15
9.10.11.12      ATTACKING    2          10:30:15

ATTACK STATISTICS:
Active VPS Nodes: 3/3
Total Attack Processes: 6
Estimated Connections: 6,000
```

## 🔧 **Konfigurasi**

### Requirements VPS
```
Minimum: 1 CPU, 1GB RAM, 10GB storage
Recommended: 2+ CPU, 2GB+ RAM, 20GB+ storage
Network: Akses outbound unrestricted
SSH: Root atau sudo privileges required
```

### Parameter Serangan
```
Connections per VPS: 100-5000 (recommended: 1000-2000)
Delay between packets: 1-60 seconds (recommended: 10-20)
Duration: 0 untuk unlimited, atau detik spesifik
```

## 🛡️ **Fitur Keamanan**

- **Encrypted Storage** - Password VPS dienkripsi dengan Fernet
- **Secure SSH** - Paramiko dengan proper key verification
- **Auto Cleanup** - File temporary dihapus setelah serangan
- **Process Isolation** - Setiap serangan berjalan independen
- **Session Management** - Complete audit trail

## 🐛 **Troubleshooting**

### Masalah Umum

**VPS Connection Failed**
```bash
# Cek koneksi SSH
ssh root@your-vps-ip

# Verifikasi credentials dan firewall settings
```

**Python
