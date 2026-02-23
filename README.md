# 🚀 AdGuard to Pi-hole DNS Sync

![Version](https://img.shields.io/badge/version-1.3.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![Pi-hole](https://img.shields.io/badge/Pi--hole-v6-red)
![AdGuard](https://img.shields.io/badge/AdGuard-Home-blue)

## 📋 Overview

This tool automatically synchronizes DNS rewrite entries from **AdGuard Home** to **Pi-hole v6**. It's perfect for homelabs running both DNS servers, ensuring consistent DNS resolution across your network.

### ✨ Key Features

- **Bi-directional Format Support**: Handles both A/AAAA records and CNAME records
- **Smart Duplicate Detection**: Automatically detects and skips existing entries
- **CNAME Short Name Support**: Properly handles CNAMEs pointing to short names (e.g., `d4rkcyber`)
- **Pi-hole v6 API Compatible**: Uses the correct Pi-hole v6 endpoints:
  - `PUT /api/config/dns/hosts/{ip}%20{domain}` for A records
  - `PUT /api/config/dns/cnameRecords/{domain},{target},{ttl}` for CNAME records
- **Session Management**: Automatic login/logout to prevent API session exhaustion
- **Docker Ready**: Fully containerized with security best practices
- **Auto-approve Mode**: Perfect for cron jobs and automation

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- Pi-hole v6 with API enabled
- AdGuard Home with API access
- Environment variables configured

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/dhaevyd/adguard-pihole-sync.git
cd adguard-pihole-sync
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables**
```bash
cp .env.example .env
nano .env
```

### Configuration (.env)

```env
# AdGuard Configuration
ADGUARD_URL=http://192.168.2.1:80/control/rewrite/list
ADGUARD_USER=your_adguard_username
ADGUARD_PASS=your_adguard_password

# Pi-hole Configuration
PIHOLE_URL=http://192.168.2.19:80
PIHOLE_PASS=your_pihole_password
```

### Usage

```bash
# Interactive mode (asks for confirmation)
python3 main.py

# Auto-approve mode (for cron jobs)
python3 main.py -y

# With Docker
docker-compose up -d
```

## 📦 Docker Deployment

```yaml
services:
  adguard-pihole-sync:
    image: ghcr.io/yourusername/adguard-pihole-sync:1.3.0
    container_name: adguard-pihole-sync
    restart: unless-stopped
    network_mode: "host"  # Required to access host network services
    environment:
      - TZ=UTC
      - ADGUARD_URL=${ADGUARD_URL}
      - ADGUARD_USER=${ADGUARD_USER}
      - ADGUARD_PASS=${ADGUARD_PASS}
      - PIHOLE_URL=${PIHOLE_URL}
      - PIHOLE_PASS=${PIHOLE_PASS}
```

### Docker Security Note
🚨 **Never bake secrets into the image!** Always pass environment variables at runtime using `.env` files or Docker secrets.

## 🔧 How It Works

1. **Fetches** all DNS rewrite entries from AdGuard Home
2. **Analyzes** each record to determine if it's an A/AAAA or CNAME record
3. **Compares** with existing Pi-hole DNS entries
4. **Syncs** only new records while preserving existing ones
5. **Handles** CNAME short names correctly (e.g., `d4rkcyber` without dots)
6. **Reports** detailed statistics of added, skipped, and duplicate records

## 📊 Sample Output

```
2026-02-23 15:18:06 - INFO - ==================================================
2026-02-23 15:18:06 - INFO - Pi-hole and AdGuard DNS Sync v1.3.0
2026-02-23 15:18:06 - INFO - ==================================================

📊 AdGuard Record Analysis:
   - A/AAAA records: 8
   - CNAME records: 36

📊 Sync Summary:
   - New A/AAAA records to add: 2
   - New CNAME records to add: 3
   - Duplicate A records (skipped): 6
   - Duplicate CNAME records (skipped): 33

🤖 Auto-approve mode: Adding all new records

📤 Adding CNAME records...
⏭️  Skipped CNAME openwrt.local.d4rkcyber.xyz -> d4rkcyber (already exists)
✅ Added CNAME new-record.local.d4rkcyber.xyz -> d4rkcyber

📋 FINAL SYNC REPORT
✅ Added: 2 A records, 1 CNAME records
⏭️  Duplicates ignored: 6 A records, 33 CNAME records
📊 Pi-hole now has 11 A records and 38 CNAME records
```

## 🎯 Version 1.3.0 - Latest Improvements

### 🚀 New Features
- **Pi-hole v6 API Optimization**: Now uses correct endpoints with URL path parameters
- **Smart CNAME Detection**: Properly handles CNAME records pointing to short names (no dots)
- **Duplicate Intelligence**: Automatically detects and gracefully handles duplicate entries
- **Session Management**: Prevents API session exhaustion with proper login/logout

### 🐛 Bug Fixes
- Fixed 404 errors by using correct API endpoints
- Resolved CNAME addition failures with proper comma-separated format
- Fixed authentication session leaks
- Corrected record type detection for short-name CNAMEs

### ⚡ Performance
- Reduced API calls with batch operations
- Faster duplicate detection using set operations
- Minimal memory footprint

## 🔄 Roadmap

- [x] Pi-hole v6 API support
- [x] CNAME short name handling
- [x] Auto-approve mode
- [x] Duplicate detection
- [ ] Webhook notifications
- [ ] Dry-run mode
- [ ] Selective record syncing

## 🛠️ Requirements

- Python 3.7+
- Pi-hole v6.0+
- AdGuard Home v0.107+
- requests library
- python-dotenv

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

MIT License - feel free to use this in your homelab!

## ⚠️ Disclaimer

This tool is not officially affiliated with Pi-hole or AdGuard. Use at your own risk in production environments.

---

**Made with ❤️ for the homelab community**
