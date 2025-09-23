# Distributed Slow HTTP Testing C2

## Peringatan Penting ⚠️

**TOOL INI HANYA UNTUK TUJUAN EDUKASI DAN TESTING YANG DIOTORISASI!**

Penggunaan tanpa izin pada sistem yang bukan milik Anda adalah **ILEGAL** dan dapat mengakibatkan tuntutan hukum. Anda bertanggung jawab penuh atas penggunaan tool ini.

## Deskripsi

Distributed Slow HTTP Testing C2 adalah sistem command & control untuk melakukan distributed slow HTTP testing menggunakan multiple VPS nodes. Tool ini dirancang untuk:

- Pentest dan security assessment yang diotorisasi
- Research keamanan jaringan
- Load testing dan stress testing
- Edukasi tentang serangan slow HTTP

### Fitur Utama

- **Multi-Platform Support**: Windows, Linux, Ubuntu, Termux
- **VPS Management**: Kelola multiple VPS Ubuntu nodes
- **Distributed Attacks**: Koordinasi serangan dari multiple IP
- **Real-time Monitoring**: Monitor status attack secara real-time
- **Multiple Attack Types**: Slowloris dan Slow POST (R.U.D.Y)
- **Security Features**: Enkripsi password dan secure database
- **Terminal Interface**: Interface terminal yang user-friendly

### Arsitektur

```
[Control Machine] --SSH--> [VPS Node 1] --HTTP--> [Target]
                  --SSH--> [VPS Node 2] --HTTP--> [Target]
                  --SSH--> [VPS Node 3] --HTTP--> [Target]
                           [VPS Node N] --HTTP--> [Target]
```

## Persyaratan Sistem

### Control Machine (Machine Anda)
- **Windows**: Windows 10/11, PowerShell 5.1+, Python 3.6+
- **Linux/Ubuntu**: Ubuntu 18.04+, Python 3.6+, OpenSSH client
- **Termux**: Android 7+, Termux app, Python 3.6+

### VPS Nodes (Untuk Attack)
- **Ubuntu 18.04/20.04/22.04 LTS** (Recommended)
- Root atau sudo access
- SSH access enabled
- Python 3.6+ installed
- Minimum 512MB RAM, 1GB storage

## Instalasi

### Windows (Command Prompt / PowerShell)

1. **Install Python dan Git**
   ```cmd
   # Download dan install Python dari https://python.org
   # Download dan install Git dari https://git-scm.com
   
   # Verify instalasi
   python --version
   git --version
   ```

2. **Download Tool**
   ```cmd
   # Opsi 1: Git Clone (Recommended)
   git clone https://github.com/YEHEZKIEL586/slowhttp-c2.git
   cd slowhttp-c2
   
   # Opsi 2: Download Manual
   # Download file dari GitHub dan extract ke folder
   ```

3. **Install Dependencies**
   ```cmd
   # Buat virtual environment
   python -m venv venv
   
   # Aktivasi virtual environment
   venv\Scripts\activate
   
   # Install requirements
   pip install -r requirements.txt
   ```

4. **Jalankan Aplikasi**
   ```cmd
   python slowhttp_c2.py
   ```

### Linux / Ubuntu (Terminal)

1. **Install Dependencies**
   ```bash
   # Update system
   sudo apt update
   
   # Install required packages
   sudo apt install python3 python3-pip python3-venv git curl wget openssh-client -y
   ```

2. **Download dan Install**
   ```bash
   # Clone repository
   git clone https://github.com/YEHEZKIEL586/slowhttp-c2.git
   cd slowhttp-c2
   
   # Jalankan auto installer
   chmod +x install.sh
   ./install.sh
   ```

3. **Jalankan Aplikasi**
   ```bash
   ./start.sh
   ```

### Termux (Android)

1. **Install Termux dan Dependencies**
   ```bash
   # Update packages
   pkg update && pkg upgrade
   
   # Install required packages
   pkg install python git curl wget openssh -y
   
   # Install pip packages
   pip install paramiko cryptography colorama
   ```

2. **Download Tool**
   ```bash
   # Clone repository
   git clone https://github.com/YEHEZKIEL586/slowhttp-c2.git
   cd slowhttp-c2
   
   # Buat virtual environment
   python -m venv venv
   source venv/bin/activate
   
   # Install requirements
   pip install -r requirements.txt
   ```

3. **Jalankan Aplikasi**
   ```bash
   python slowhttp_c2.py
   ```

## Setup VPS Ubuntu

### Persiapan VPS (Untuk Attack Nodes)

1. **Update System**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Python**
   ```bash
   sudo apt install python3 python3-pip -y
   ```

3. **Enable SSH Access**
   ```bash
   # Pastikan SSH service running
   sudo systemctl status ssh
   sudo systemctl enable ssh
   
   # Configure SSH (optional)
   sudo nano /etc/ssh/sshd_config
   sudo systemctl restart ssh
   ```

4. **Create User (Optional)**
   ```bash
   # Buat user khusus untuk testing
   sudo useradd -m -s /bin/bash testuser
   sudo passwd testuser
   sudo usermod -aG sudo testuser
   ```

## Panduan Penggunaan

### 1. Menjalankan Aplikasi

```bash
# Linux/Ubuntu/Termux
./start.sh

# Windows
python slowhttp_c2.py
```

### 2. VPS Management

1. **Add VPS Node**
   - Pilih menu "VPS Management" → "Add VPS Node"
   - Masukkan IP address VPS
   - Masukkan SSH username dan password
   - Masukkan SSH port (default: 22)
   - Masukkan lokasi VPS (optional)

2. **Test Connections**
   - Pilih "Test All Connections" untuk test semua VPS
   - Atau "Test Single VPS" untuk test VPS tertentu

3. **Deploy Agents**
   - Pilih "Deploy Agents to All" untuk install attack agents
   - Agents akan diinstall di `/tmp/slowhttp_c2/agent.py`

### 3. Launch Attack

1. **Konfigurasi Target**
   - Pilih menu "Launch Distributed Attack"
   - Masukkan target URL (contoh: `http://target.com`)
   - **PASTIKAN ANDA MEMILIKI IZIN UNTUK TEST TARGET TERSEBUT**

2. **Pilih Attack Type**
   - **Slowloris**: Slow HTTP headers attack
   - **Slow POST**: R.U.D.Y attack (slow POST data)

3. **Konfigurasi Parameters**
   - **Connections per VPS**: Jumlah koneksi per VPS (default: 1000)
   - **Delay**: Delay antar packet dalam detik (default: 15)
   - **Duration**: Durasi attack dalam detik (0 = unlimited)

4. **Monitor Attack**
   - Setelah launch, gunakan "Monitor Active Attacks"
   - Lihat status real-time dari semua VPS nodes
   - Tekan Ctrl+C untuk stop monitoring
   - Ketik 'y' untuk stop attack

### 4. Management Features

- **Attack History**: Lihat riwayat semua attack sessions
- **System Status**: Cek status VPS nodes dan SSH connections
- **Remove VPS**: Hapus VPS node dari database

## Konfigurasi Advanced

### Environment Variables
```bash
# Set custom database location
export SLOWHTTP_DB="/path/to/database.db"

# Set custom log level
export SLOWHTTP_LOG_LEVEL="DEBUG"
```

### Configuration File (Optional)
Buat file `config.ini`:
```ini
[database]
file = c2_database.db

[security]
key_file = key.key

[logging]
level = INFO
file = logs/slowhttp.log

[ssh]
timeout = 30
max_connections = 50
```

## Troubleshooting

### Error Umum dan Solusi

1. **"Virtual environment not found"**
   ```bash
   # Reinstall virtual environment
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   ```

2. **"SSH connection failed"**
   - Pastikan SSH service running di VPS
   - Check firewall settings
   - Verify username/password/port
   - Test manual SSH: `ssh username@vps_ip`

3. **"Permission denied" di VPS**
   ```bash
   # Fix permissions di VPS
   sudo chown -R $USER:$USER /tmp/slowhttp_c2
   chmod +x /tmp/slowhttp_c2/agent.py
   ```

4. **"ModuleNotFoundError"**
   ```bash
   # Install missing dependencies
   pip install paramiko cryptography colorama
   ```

5. **"Database locked"**
   ```bash
   # Stop all instances dan restart
   pkill -f slowhttp_c2
   rm -f c2_database.db-journal
   ```

### Debugging Mode

```bash
# Jalankan dengan verbose logging
python slowhttp_c2.py --debug

# Check log files
tail -f logs/slowhttp.log
```

## FAQ

### Q: Apakah legal menggunakan tool ini?
**A**: Tool ini legal **HANYA** untuk testing sistem yang Anda miliki atau memiliki izin tertulis untuk test. Penggunaan tanpa izin adalah ilegal.

### Q: Berapa VPS yang dibutuhkan untuk attack efektif?
**A**: Tergantung target dan tujuan testing. Untuk testing basic, 2-5 VPS sudah cukup. Untuk testing yang lebih intensive, bisa menggunakan 10-50 VPS.

### Q: Kenapa attack tidak efektif?
**A**: Kemungkinan:
- Target memiliki DDoS protection
- Rate limiting di server target
- Firewall memblokir koneksi
- VPS ter-blacklist
- Konfigurasi attack perlu disesuaikan

### Q: Bagaimana cara menghentikan attack?
**A**: 
1. Masuk ke "Monitor Active Attacks"
2. Tekan Ctrl+C
3. Pilih 'y' untuk stop attack
4. Atau restart VPS jika diperlukan

### Q: Apakah tool ini meninggalkan jejak di VPS?
**A**: Ya, agents disimpan di `/tmp/slowhttp_c2/`. Untuk cleanup:
```bash
rm -rf /tmp/slowhttp_c2/
pkill -f agent.py
```

### Q: Bisakah menggunakan VPS dengan OS selain Ubuntu?
**A**: Tool dirancang untuk Ubuntu, tapi bisa berjalan di CentOS/Debian dengan sedikit modifikasi. Windows VPS tidak didukung.

## Best Practices

### Security
- Gunakan VPS dengan SSH key authentication
- Regularly update VPS dan control machine
- Gunakan strong passwords
- Monitor VPS untuk aktivitas suspicious
- Backup database secara berkala

### Performance
- Distribute VPS di lokasi geografis berbeda
- Monitor resource usage VPS
- Sesuaikan connection count dengan kapasitas VPS
- Gunakan delay yang reasonable untuk menghindari detection

### Legal & Ethical
- **SELALU** dapatkan izin tertulis sebelum testing
- Dokumentasikan semua testing activities
- Inform target tentang testing schedule
- Stop immediately jika diminta
- Report findings secara responsible

## Log Files

### Location
- **Linux/Ubuntu**: `logs/slowhttp.log`
- **Windows**: `logs\slowhttp.log`
- **Termux**: `logs/slowhttp.log`

### Log Levels
- `ERROR`: Error messages
- `WARNING`: Warning messages  
- `INFO`: General information
- `DEBUG`: Detailed debugging info

### Log Format
```
[2024-01-15 10:30:45] [INFO] VPS 192.168.1.100: Connection established
[2024-01-15 10:30:46] [INFO] Agent deployed successfully to 192.168.1.100
[2024-01-15 10:31:00] [INFO] Attack session 123 started on target.com
[2024-01-15 10:31:01] [WARNING] VPS 192.168.1.101: Connection timeout
```

## Update dan Maintenance

### Update Tool
```bash
# Linux/Ubuntu
./update.sh

# Windows
git pull origin main
pip install --upgrade -r requirements.txt

# Termux  
git pull origin main
pip install --upgrade -r requirements.txt
```

### Backup Database
```bash
# Backup database
cp c2_database.db c2_database_backup_$(date +%Y%m%d).db

# Restore database
cp c2_database_backup_20240115.db c2_database.db
```

### Clean Installation
```bash
# Linux/Ubuntu
./uninstall.sh

# Manual cleanup
rm -rf ~/slowhttp-c2
rm -rf ~/.slowhttp-c2
```

## Kontribusi

Jika Anda menemukan bug atau ingin berkontribusi:

1. Fork repository
2. Buat feature branch
3. Commit changes
4. Push ke branch
5. Create Pull Request

## Lisensi

Tool ini dirilis untuk tujuan edukasi. Penggunaan untuk tujuan ilegal tidak didukung dan sepenuhnya menjadi tanggung jawab user.

## Disclaimer

- Tool ini disediakan "AS IS" tanpa warranty
- Developer tidak bertanggung jawab atas penyalahgunaan tool
- Selalu patuhi hukum dan regulasi yang berlaku
- Gunakan hanya untuk testing yang diotorisasi

## Kontak

Untuk pertanyaan atau issue, buka GitHub Issues atau hubungi developer.

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally!**
