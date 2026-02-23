#!/usr/bin/env python3
import os
import requests
import sys
import logging
import time
import json
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
import ipaddress
import urllib.parse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# -----------------------------
# Environment variables
# -----------------------------
ADGUARD_URL = os.getenv("ADGUARD_URL")
ADGUARD_USER = os.getenv("ADGUARD_USER")
ADGUARD_PASS = os.getenv("ADGUARD_PASS")

PIHOLE_URL = os.getenv("PIHOLE_URL")
PIHOLE_PASS = os.getenv("PIHOLE_PASS")

# Parse command line arguments
AUTO_APPROVE = "-y" in sys.argv or "--yes" in sys.argv
PRUNE_MODE = "--prune" in sys.argv
DRY_RUN = "--dry-run" in sys.argv
VERSION = "1.5.0"

# Database file (will be created automatically)
DB_FILE = os.getenv("DB_FILE", "adguard-sync.db")

# -----------------------------
# Database Manager (Auto-creates tables)
# -----------------------------
class SyncDatabase:
    """Manages SQLite database for tracking synced records."""
    
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Create database and tables if they don't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create A records table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS a_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain, ip)
                )
            ''')
            
            # Create CNAME records table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cname_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    target TEXT NOT NULL,
                    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain, target)
                )
            ''')
            
            # Create sync history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sync_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sync_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    a_added INTEGER DEFAULT 0,
                    a_removed INTEGER DEFAULT 0,
                    cname_added INTEGER DEFAULT 0,
                    cname_removed INTEGER DEFAULT 0,
                    status TEXT
                )
            ''')
            
            conn.commit()
            logger.info(f"📁 Database initialized: {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
        finally:
            conn.close()
    
    def is_first_run(self):
        """Check if database is empty (first run)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM a_records")
            a_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM cname_records")
            cname_count = cursor.fetchone()[0]
            return a_count == 0 and cname_count == 0
        except Exception as e:
            logger.warning(f"Failed to check first run: {e}")
            return True
        finally:
            conn.close()
    
    def record_a_sync(self, domain, ip):
        """Record an A record that was synced."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO a_records (domain, ip, synced_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (domain, ip)
            )
            conn.commit()
            logger.debug(f"✅ DB: Tracked A {domain} -> {ip}")
            return True
        except Exception as e:
            logger.error(f"❌ DB Error recording A record {domain}: {e}")
            return False
        finally:
            conn.close()
    
    def record_cname_sync(self, domain, target):
        """Record a CNAME record that was synced."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO cname_records (domain, target, synced_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (domain, target)
            )
            conn.commit()
            logger.debug(f"✅ DB: Tracked CNAME {domain} -> {target}")
            return True
        except Exception as e:
            logger.error(f"❌ DB Error recording CNAME record {domain}: {e}")
            return False
        finally:
            conn.close()
    
    def get_synced_a_records(self):
        """Get all A records that have been synced."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT domain, ip FROM a_records")
            return {f"{ip} {domain}" for domain, ip in cursor.fetchall()}
        except Exception as e:
            logger.warning(f"Failed to get synced A records: {e}")
            return set()
        finally:
            conn.close()
    
    def get_synced_cname_records(self):
        """Get all CNAME records that have been synced."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT domain, target FROM cname_records")
            return {f"{domain} -> {target}" for domain, target in cursor.fetchall()}
        except Exception as e:
            logger.warning(f"Failed to get synced CNAME records: {e}")
            return set()
        finally:
            conn.close()
    
    def remove_a_record(self, domain, ip):
        """Remove an A record from tracking (when pruned)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM a_records WHERE domain = ? AND ip = ?", (domain, ip))
            conn.commit()
            logger.debug(f"🗑️ DB: Removed A {domain}")
            return True
        except Exception as e:
            logger.warning(f"Failed to remove A record: {e}")
            return False
        finally:
            conn.close()
    
    def remove_cname_record(self, domain, target):
        """Remove a CNAME record from tracking (when pruned)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cname_records WHERE domain = ? AND target = ?", (domain, target))
            conn.commit()
            logger.debug(f"🗑️ DB: Removed CNAME {domain}")
            return True
        except Exception as e:
            logger.warning(f"Failed to remove CNAME record: {e}")
            return False
        finally:
            conn.close()
    
    def log_sync(self, a_added, a_removed, cname_added, cname_removed, status="success"):
        """Log a sync operation to history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sync_history 
                (a_added, a_removed, cname_added, cname_removed, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (a_added, a_removed, cname_added, cname_removed, status))
            conn.commit()
        except Exception as e:
            logger.warning(f"Failed to log sync: {e}")
        finally:
            conn.close()
    
    def get_stats(self):
        """Get sync statistics."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM a_records")
            a_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM cname_records")
            cname_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sync_history")
            history_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT MAX(sync_time) FROM sync_history")
            last_sync = cursor.fetchone()[0]
            
            return {
                'a_records': a_count,
                'cname_records': cname_count,
                'total_syncs': history_count,
                'last_sync': last_sync or 'Never'
            }
        except Exception as e:
            logger.warning(f"Failed to get stats: {e}")
            return {}
        finally:
            conn.close()

# -----------------------------
# Pi-hole API Functions
# -----------------------------
class PiHoleSession:
    def __init__(self, base_url, password):
        self.base_url = base_url
        self.password = password
        self.session = requests.Session()
        self.sid = None
        self.csrf = None
        self.headers = {}
    
    def __enter__(self):
        self.login()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()
    
    def login(self):
        """Authenticate to Pi-hole."""
        url = f"{self.base_url}/api/auth"
        
        logger.info(f"Authenticating to Pi-hole at {url}")
        try:
            resp = self.session.post(url, json={"password": self.password}, timeout=10)
            resp.raise_for_status()
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to Pi-hole at {self.base_url}")
            sys.exit(1)
        except requests.exceptions.Timeout:
            logger.error("Connection to Pi-hole timed out")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.error("Pi-hole API seats exhausted. Clear sessions in Pi-hole admin.")
            sys.exit(1)
        
        data = resp.json()
        if not data.get("session", {}).get("valid"):
            logger.error("Pi-hole authentication failed")
            sys.exit(1)
        
        self.sid = data["session"]["sid"]
        self.csrf = data["session"]["csrf"]
        self.headers = {
            "X-FTL-SID": self.sid,
            "X-CSRF-TOKEN": self.csrf,
            "Content-Type": "application/json"
        }
        logger.info("✅ Pi-hole authentication successful")
    
    def logout(self):
        """Logout from Pi-hole."""
        if not self.sid:
            return
        url = f"{self.base_url}/api/auth"
        try:
            self.session.delete(url, headers=self.headers, timeout=5)
            logger.info("✅ Successfully logged out from Pi-hole")
        except:
            pass
    
    def get_all_records(self):
        """Get all DNS records from Pi-hole."""
        url = f"{self.base_url}/api/config"
        resp = self.session.get(url, headers=self.headers)
        resp.raise_for_status()
        data = resp.json()
        
        hosts = data.get('config', {}).get('dns', {}).get('hosts', [])
        cname_records = data.get('config', {}).get('dns', {}).get('cnameRecords', [])
        
        # Parse A records
        a_records = set()
        for host in hosts:
            if isinstance(host, str) and ' ' in host:
                a_records.add(host)
        
        # Parse CNAME records
        cname_set = set()
        for cname in cname_records:
            if isinstance(cname, str) and ',' in cname:
                # Format: "domain,target"
                parts = cname.split(',')
                if len(parts) >= 2:
                    cname_set.add(f"{parts[0]} -> {parts[1]}")
        
        return a_records, cname_set
    
    def add_a_record(self, ip, domain):
        """Add A record with detailed error logging."""
        encoded = f"{ip}%20{domain}"
        url = f"{self.base_url}/api/config/dns/hosts/{encoded}"
        
        try:
            resp = self.session.put(url, headers=self.headers)
            if resp.status_code in [200, 204]:
                logger.info(f"   ✅ Added A: {domain} -> {ip}")
                return True
            else:
                logger.error(f"   ❌ Failed to add A: {domain} -> {ip}")
                logger.error(f"      HTTP {resp.status_code}")
                logger.error(f"      Response: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"   ❌ Exception adding A: {domain} -> {ip}")
            logger.error(f"      Error: {e}")
            return False
    
    def delete_a_record(self, ip, domain):
        """Delete A record with detailed error logging."""
        encoded = f"{ip}%20{domain}"
        url = f"{self.base_url}/api/config/dns/hosts/{encoded}"
        
        try:
            resp = self.session.delete(url, headers=self.headers)
            if resp.status_code in [200, 204]:
                logger.info(f"   ✅ Deleted A: {domain}")
                return True
            else:
                logger.error(f"   ❌ Failed to delete A: {domain}")
                logger.error(f"      HTTP {resp.status_code}")
                logger.error(f"      Response: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"   ❌ Exception deleting A: {domain}")
            logger.error(f"      Error: {e}")
            return False
    
    def add_cname_record(self, domain, target):
        """Add CNAME record with detailed error logging."""
        encoded = f"{domain},{target}"
        url = f"{self.base_url}/api/config/dns/cnameRecords/{encoded}"
        
        try:
            resp = self.session.put(url, headers=self.headers)
            if resp.status_code in [200, 204]:
                logger.info(f"   ✅ Added CNAME: {domain} -> {target}")
                return True
            else:
                logger.error(f"   ❌ Failed to add CNAME: {domain} -> {target}")
                logger.error(f"      HTTP {resp.status_code}")
                logger.error(f"      Response: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"   ❌ Exception adding CNAME: {domain} -> {target}")
            logger.error(f"      Error: {e}")
            return False
    
    def delete_cname_record(self, domain, target):
        """Delete CNAME record with detailed error logging."""
        encoded = f"{domain},{target}"
        url = f"{self.base_url}/api/config/dns/cnameRecords/{encoded}"
        
        try:
            resp = self.session.delete(url, headers=self.headers)
            if resp.status_code in [200, 204]:
                logger.info(f"   ✅ Deleted CNAME: {domain}")
                return True
            else:
                logger.error(f"   ❌ Failed to delete CNAME: {domain}")
                logger.error(f"      HTTP {resp.status_code}")
                logger.error(f"      Response: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"   ❌ Exception deleting CNAME: {domain}")
            logger.error(f"      Error: {e}")
            return False

# -----------------------------
# AdGuard Functions
# -----------------------------
def fetch_adguard_rewrites():
    """Fetch all DNS rewrites from AdGuard."""
    logger.info(f"Fetching AdGuard rewrites from {ADGUARD_URL}")
    try:
        resp = requests.get(ADGUARD_URL, auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"✅ Successfully fetched {len(data)} records")
        return data
    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to AdGuard at {ADGUARD_URL}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to fetch AdGuard rewrites: {e}")
        raise

def determine_record_type(record):
    """Determine if record is A or CNAME."""
    if not isinstance(record, dict):
        return 'UNKNOWN'
    
    answer = None
    domain = None
    
    for field in ['domain', 'host', 'name']:
        if field in record:
            domain = str(record[field]).rstrip('.')
            break
    
    for field in ['answer', 'ip', 'target']:
        if field in record:
            answer = str(record[field]).rstrip('.')
            break
    
    if not domain or not answer:
        return 'UNKNOWN'
    
    try:
        ipaddress.ip_address(answer)
        return 'AAAA' if ':' in answer else 'A'
    except:
        return 'CNAME'

def categorize_adguard_records(records):
    """Split records into A and CNAME lists."""
    a_records = []
    cname_records = []
    
    for record in records:
        rtype = determine_record_type(record)
        domain = record.get('domain', '').rstrip('.')
        answer = record.get('answer', '').rstrip('.')
        
        if rtype in ['A', 'AAAA']:
            a_records.append({'domain': domain, 'ip': answer})
        elif rtype == 'CNAME':
            cname_records.append({'domain': domain, 'target': answer})
    
    return a_records, cname_records

def convert_to_set(records, rtype):
    """Convert records to set for comparison."""
    if rtype == 'A':
        return {f"{r['ip']} {r['domain']}" for r in records}
    return {f"{r['domain']} -> {r['target']}" for r in records}

# -----------------------------
# Main Sync Function
# -----------------------------
def sync_records(adguard_records, pihole, db):
    """Sync records from AdGuard to Pi-hole."""
    
    start_time = time.time()
    logger.info("=" * 50)
    logger.info("Starting DNS sync")
    
    # Parse AdGuard records
    a_records, cname_records = categorize_adguard_records(adguard_records)
    adguard_a = convert_to_set(a_records, 'A')
    adguard_cname = convert_to_set(cname_records, 'CNAME')
    
    # Get current Pi-hole records (LIVE check)
    pihole_a, pihole_cname = pihole.get_all_records()
    
    # Check if this is first run and populate database if needed
    is_first = db.is_first_run()
    if is_first and (pihole_a or pihole_cname):
        logger.info("\n📋 First run detected - Populating database with existing Pi-hole records...")
        
        # Parse and add all A records
        for record in pihole_a:
            ip, domain = record.split(' ', 1)
            if db.record_a_sync(domain, ip):
                logger.info(f"   📝 Tracked A: {domain} -> {ip}")
            else:
                logger.error(f"   ❌ Failed to track A: {domain}")
        
        # Parse and add all CNAME records
        for record in pihole_cname:
            domain, target = record.split(' -> ', 1)
            if db.record_cname_sync(domain, target):
                logger.info(f"   📝 Tracked CNAME: {domain} -> {target}")
            else:
                logger.error(f"   ❌ Failed to track CNAME: {domain}")
        
        logger.info(f"✅ Database population complete")
    
    # Get database records (what we've synced before)
    db_a = db.get_synced_a_records()
    db_cname = db.get_synced_cname_records()
    
    logger.info(f"\n📊 Record Summary:")
    logger.info(f"   - AdGuard A: {len(adguard_a)}")
    logger.info(f"   - AdGuard CNAME: {len(adguard_cname)}")
    logger.info(f"   - Pi-hole A: {len(pihole_a)}")
    logger.info(f"   - Pi-hole CNAME: {len(pihole_cname)}")
    logger.info(f"   - Database A: {len(db_a)}")
    logger.info(f"   - Database CNAME: {len(db_cname)}")
    
    # Find what needs to be added (in AdGuard but not in Pi-hole)
    a_to_add = adguard_a - pihole_a
    cname_to_add = adguard_cname - pihole_cname
    
    # Find what needs to be removed
    # Records that are:
    # 1. In our database (we synced them before)
    # 2. Not in AdGuard anymore (deleted from source)
    # 3. STILL in Pi-hole (haven't been manually removed)
    a_to_remove = set()
    cname_to_remove = set()
    
    if PRUNE_MODE:
        a_to_remove = (db_a - adguard_a) & pihole_a
        cname_to_remove = (db_cname - adguard_cname) & pihole_cname
    
    logger.info(f"\n📊 Changes:")
    logger.info(f"   - Add A: {len(a_to_add)}")
    logger.info(f"   - Add CNAME: {len(cname_to_add)}")
    if PRUNE_MODE:
        logger.info(f"   - Remove A: {len(a_to_remove)}")
        logger.info(f"   - Remove CNAME: {len(cname_to_remove)}")
    
    if DRY_RUN:
        logger.info("\n🔍 DRY RUN - No changes will be made")
        if a_to_add:
            logger.info("\n📋 Would add A records:")
            for record in sorted(list(a_to_add))[:5]:
                logger.info(f"   + {record}")
        if cname_to_add:
            logger.info("\n📋 Would add CNAME records:")
            for record in sorted(list(cname_to_add))[:5]:
                logger.info(f"   + {record}")
        if PRUNE_MODE and (a_to_remove or cname_to_remove):
            logger.info("\n📋 Would remove:")
            for record in sorted(list(a_to_remove))[:5]:
                logger.info(f"   - {record}")
            for record in sorted(list(cname_to_remove))[:5]:
                logger.info(f"   - {record}")
        return True
    
    # No changes needed
    if not a_to_add and not cname_to_add and not a_to_remove and not cname_to_remove:
        logger.info("\n✅ Already in sync! No changes needed.")
        return True
    
    # Confirm if not auto-approve
    if not AUTO_APPROVE:
        action = "add"
        if PRUNE_MODE and (a_to_remove or cname_to_remove):
            action = "add and remove"
        
        response = input(f"\n🔄 {action} {len(a_to_add)} A, {len(cname_to_add)} CNAME" +
                        (f" and REMOVE {len(a_to_remove)} A, {len(cname_to_remove)} CNAME" if PRUNE_MODE else "") + 
                        "? (y/N): ")
        if response.lower() != 'y':
            logger.info("❌ Cancelled")
            return False
    
    # Track stats
    a_added = 0
    a_removed = 0
    cname_added = 0
    cname_removed = 0
    
    # Remove old records first (prune mode only)
    if PRUNE_MODE and (a_to_remove or cname_to_remove):
        logger.info("\n🗑️  Removing orphaned records...")
        
        # Remove A records
        for record_str in a_to_remove:
            ip, domain = record_str.split(' ', 1)
            if pihole.delete_a_record(ip, domain):
                db.remove_a_record(domain, ip)
                a_removed += 1
            else:
                logger.info(f"   ❌ Failed to remove A: {domain}")
        
        # Remove CNAME records
        for record_str in cname_to_remove:
            domain, target = record_str.split(' -> ', 1)
            if pihole.delete_cname_record(domain, target):
                db.remove_cname_record(domain, target)
                cname_removed += 1
            else:
                logger.info(f"   ❌ Failed to remove CNAME: {domain}")
    
    # Add new records
    if a_to_add:
        logger.info("\n📤 Adding A records...")
        a_dict = {f"{r['ip']} {r['domain']}": r for r in a_records}
        for record_str in a_to_add:
            r = a_dict[record_str]
            if pihole.add_a_record(r['ip'], r['domain']):
                db.record_a_sync(r['domain'], r['ip'])
                a_added += 1
    
    if cname_to_add:
        logger.info("\n📤 Adding CNAME records...")
        c_dict = {f"{r['domain']} -> {r['target']}": r for r in cname_records}
        for record_str in cname_to_add:
            r = c_dict[record_str]
            if pihole.add_cname_record(r['domain'], r['target']):
                db.record_cname_sync(r['domain'], r['target'])
                cname_added += 1
    
    # Log to history
    status = "success" if (a_added + cname_added + a_removed + cname_removed) > 0 else "no_changes"
    db.log_sync(a_added, a_removed, cname_added, cname_removed, status)
    
    # Final report
    elapsed = time.time() - start_time
    logger.info("\n" + "=" * 50)
    logger.info(f"📋 SYNC REPORT - v{VERSION}")
    logger.info("=" * 50)
    
    if a_added > 0 or cname_added > 0:
        logger.info(f"✅ Added: {a_added} A, {cname_added} CNAME")
    if PRUNE_MODE and (a_removed > 0 or cname_removed > 0):
        logger.info(f"🗑️  Removed: {a_removed} A, {cname_removed} CNAME")
    
    logger.info(f"⏱️  Time: {elapsed:.2f} seconds")
    
    # Show final stats
    stats = db.get_stats()
    logger.info(f"\n📊 Database stats:")
    logger.info(f"   - Tracked A: {stats.get('a_records', 0)}")
    logger.info(f"   - Tracked CNAME: {stats.get('cname_records', 0)}")
    logger.info(f"   - Total syncs: {stats.get('total_syncs', 0)}")
    logger.info(f"   - Last sync: {stats.get('last_sync', 'Never')}")
    
    return True

# -----------------------------
# Main
# -----------------------------
def main():
    logger.info("=" * 50)
    logger.info(f"Pi-hole and AdGuard DNS Sync v{VERSION}")
    logger.info("=" * 50)
    
    # Initialize database (auto-creates)
    db = SyncDatabase()
    
    if AUTO_APPROVE:
        logger.info("🤖 Auto-approve mode enabled")
    if PRUNE_MODE:
        logger.info("🗑️  Prune mode enabled")
    if DRY_RUN:
        logger.info("🔍 Dry run mode enabled")
    
    # Show DB location
    logger.info(f"📁 Database: {os.path.abspath(DB_FILE)}")
    
    # Validate env vars
    required = [ADGUARD_URL, ADGUARD_USER, ADGUARD_PASS, PIHOLE_URL, PIHOLE_PASS]
    if not all(required):
        logger.error("Missing environment variables")
        logger.error("Check: ADGUARD_URL, ADGUARD_USER, ADGUARD_PASS, PIHOLE_URL, PIHOLE_PASS")
        sys.exit(1)
    
    logger.info(f"\n📡 Pi-hole: {PIHOLE_URL}")
    logger.info(f"📡 AdGuard: {ADGUARD_URL}")
    
    try:
        # Fetch AdGuard records
        adguard_records = fetch_adguard_rewrites()
        
        # Sync with Pi-hole
        with PiHoleSession(PIHOLE_URL, PIHOLE_PASS) as pihole:
            sync_records(adguard_records, pihole, db)
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ Interrupted")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()