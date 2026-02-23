#!/usr/bin/env python3
import os
import requests
import sys
import logging
import time
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

# -----------------------------
# Helper Functions
# -----------------------------
def is_ip_address(value):
    """Check if a string is an IP address (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def determine_record_type(adguard_record):
    """Determine if an AdGuard record is A/AAAA or CNAME based on answer format."""
    
    if not isinstance(adguard_record, dict):
        return 'UNKNOWN'
    
    answer = None
    domain = None
    
    for domain_field in ['domain', 'host', 'name', 'record']:
        if domain_field in adguard_record:
            domain = adguard_record[domain_field]
            break
    
    for answer_field in ['answer', 'ip', 'address', 'value', 'target', 'destination']:
        if answer_field in adguard_record:
            answer = adguard_record[answer_field]
            break
    
    if not domain or not answer:
        return 'UNKNOWN'
    
    domain = str(domain).rstrip('.')
    answer = str(answer).rstrip('.')
    
    try:
        ipaddress.ip_address(answer)
        return 'AAAA' if ':' in answer else 'A'
    except ValueError:
        pass
    
    if answer and ' ' not in answer:
        return 'CNAME'
    
    return 'UNKNOWN'

# -----------------------------
# Pi-hole API Functions with Session Management
# -----------------------------
class PiHoleSession:
    """Manages Pi-hole API session with automatic login/logout."""
    
    def __init__(self, base_url, password):
        self.base_url = base_url
        self.password = password
        self.session = requests.Session()
        self.sid = None
        self.csrf = None
        self.headers = {}
    
    def __enter__(self):
        """Context manager entry - login"""
        self.login()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - logout"""
        self.logout()
    
    def login(self):
        """Authenticate to Pi-hole API and get session token."""
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
                logger.error("Pi-hole API seats exhausted. Please clear sessions in Pi-hole admin.")
                logger.error("Go to: Settings → Web/API → Remove all sessions")
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
        """Logout from Pi-hole API to free up the session seat."""
        if not self.sid:
            return
        
        url = f"{self.base_url}/api/auth"
        try:
            resp = self.session.delete(url, headers=self.headers, timeout=5)
            if resp.status_code == 204:
                logger.info("✅ Successfully logged out from Pi-hole")
        except Exception as e:
            logger.warning(f"Error during logout: {e}")
    
    def get_all_records(self):
        """Get all DNS records (hosts and CNAMEs) from Pi-hole."""
        url = f"{self.base_url}/api/config"
        
        logger.info("Fetching existing DNS records...")
        try:
            resp = self.session.get(url, headers=self.headers)
            resp.raise_for_status()
            data = resp.json()
            
            config = data.get('config', {})
            dns = config.get('dns', {})
            
            hosts = dns.get('hosts', [])
            cname_records = dns.get('cnameRecords', [])
            
            # Parse hosts into a set for easy comparison
            a_records = set()
            for host in hosts:
                if isinstance(host, str) and ' ' in host:
                    a_records.add(host)
            
            # Parse CNAME records into a set
            cname_set = set()
            for cname in cname_records:
                if isinstance(cname, str) and ',' in cname:
                    # Format: "domain,target,ttl"
                    parts = cname.split(',')
                    if len(parts) >= 2:
                        cname_set.add(f"{parts[0]} -> {parts[1]}")
            
            logger.info(f"Found {len(a_records)} A/AAAA records and {len(cname_set)} CNAME records")
            return a_records, cname_set
            
        except Exception as e:
            logger.error(f"Failed to fetch DNS records: {e}")
            return set(), set()
    
    def add_a_record(self, ip, domain, ignore_duplicates=True):
        """Add a single A record to Pi-hole using PUT with path parameters."""
        # URL encode the space between IP and domain
        encoded_record = f"{ip}%20{domain}"
        url = f"{self.base_url}/api/config/dns/hosts/{encoded_record}"
        
        try:
            resp = self.session.put(url, headers=self.headers)
            if resp.status_code in [200, 204]:
                logger.info(f"✅ Added A record {domain} -> {ip}")
                return True, 'added'
            elif resp.status_code == 409:
                if ignore_duplicates:
                    logger.info(f"⏭️  Skipped A record {domain} -> {ip} (already exists)")
                    return True, 'exists'
                else:
                    logger.warning(f"⚠️  Duplicate A record {domain} -> {ip}")
                    return False, 'duplicate'
            else:
                logger.error(f"Failed to add A record {domain}: HTTP {resp.status_code}")
                if resp.text:
                    logger.error(f"Response: {resp.text}")
                return False, 'error'
        except Exception as e:
            logger.error(f"Error adding A record {domain}: {e}")
            return False, 'error'
    
    def add_cname_record(self, domain, target, ttl=330, ignore_duplicates=True):
        """Add a single CNAME record to Pi-hole using PUT with path parameters."""
        # Format: domain,target,ttl (commas, no spaces)
        encoded_record = f"{domain},{target},{ttl}"
        url = f"{self.base_url}/api/config/dns/cnameRecords/{encoded_record}"
        
        try:
            resp = self.session.put(url, headers=self.headers)
            if resp.status_code in [200, 204]:
                logger.info(f"✅ Added CNAME {domain} -> {target}")
                return True, 'added'
            elif resp.status_code == 409:
                if ignore_duplicates:
                    logger.info(f"⏭️  Skipped CNAME {domain} -> {target} (already exists)")
                    return True, 'exists'
                else:
                    logger.warning(f"⚠️  Duplicate CNAME {domain} -> {target}")
                    return False, 'duplicate'
            else:
                # Check if it's a duplicate from the error message
                if resp.status_code == 400 and resp.text and 'duplicate' in resp.text.lower():
                    if ignore_duplicates:
                        logger.info(f"⏭️  Skipped CNAME {domain} -> {target} (already exists)")
                        return True, 'exists'
                    else:
                        logger.warning(f"⚠️  Duplicate CNAME {domain} -> {target}")
                        return False, 'duplicate'
                
                logger.error(f"Failed to add CNAME {domain}: HTTP {resp.status_code}")
                if resp.text:
                    logger.error(f"Response: {resp.text}")
                return False, 'error'
        except Exception as e:
            logger.error(f"Error adding CNAME {domain}: {e}")
            return False, 'error'

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

def categorize_adguard_records(adguard_records):
    """Split AdGuard records into A and CNAME categories."""
    a_records = []
    cname_records = []
    unknown_records = []
    
    for record in adguard_records:
        try:
            record_type = determine_record_type(record)
            
            if not isinstance(record, dict):
                unknown_records.append(record)
                continue
            
            domain = None
            for field in ['domain', 'host', 'name']:
                if field in record and record[field]:
                    domain = str(record[field]).rstrip('.')
                    break
            
            answer = None
            for field in ['answer', 'ip', 'target', 'address', 'value']:
                if field in record and record[field]:
                    answer = str(record[field]).rstrip('.')
                    break
            
            if not domain or not answer:
                unknown_records.append(record)
                continue
            
            if record_type in ['A', 'AAAA']:
                a_records.append({
                    'domain': domain,
                    'ip': answer,
                    'type': record_type
                })
            elif record_type == 'CNAME':
                cname_records.append({
                    'domain': domain,
                    'target': answer,
                    'type': 'CNAME'
                })
            else:
                unknown_records.append(record)
                
        except Exception as e:
            logger.warning(f"Error processing record: {e}")
            unknown_records.append(record)
    
    return a_records, cname_records, unknown_records

# -----------------------------
# Main Sync Function
# -----------------------------
def sync_records(adguard_records, pihole_session):
    """Sync both A and CNAME records from AdGuard to Pi-hole."""
    
    start_time = time.time()
    logger.info("=" * 50)
    logger.info("Starting DNS sync")
    
    a_records, cname_records, unknown = categorize_adguard_records(adguard_records)
    
    logger.info(f"\n📊 AdGuard Record Analysis:")
    logger.info(f"   - A/AAAA records: {len(a_records)}")
    logger.info(f"   - CNAME records: {len(cname_records)}")
    if unknown:
        logger.info(f"   - Unknown type: {len(unknown)}")
    
    # Get current Pi-hole records
    pihole_a, pihole_cname = pihole_session.get_all_records()
    
    # Convert Pi-hole A records to a set of strings for comparison
    pihole_a_set = pihole_a
    
    # Convert Pi-hole CNAME records to a set of strings for comparison
    pihole_cname_set = pihole_cname
    
    # Find new A records to add
    a_to_add = []
    a_duplicates = []
    for record in a_records:
        record_str = f"{record['ip']} {record['domain']}"
        if record_str not in pihole_a_set:
            a_to_add.append(record)
        else:
            a_duplicates.append(record)
    
    # Find new CNAME records to add
    cname_to_add = []
    cname_duplicates = []
    for record in cname_records:
        record_str = f"{record['domain']} -> {record['target']}"
        if record_str not in pihole_cname_set:
            cname_to_add.append(record)
        else:
            cname_duplicates.append(record)
    
    logger.info(f"\n📊 Sync Summary:")
    logger.info(f"   - New A/AAAA records to add: {len(a_to_add)}")
    logger.info(f"   - New CNAME records to add: {len(cname_to_add)}")
    logger.info(f"   - Duplicate A records (skipped): {len(a_duplicates)}")
    logger.info(f"   - Duplicate CNAME records (skipped): {len(cname_duplicates)}")
    
    if not a_to_add and not cname_to_add:
        logger.info("\n✅ Already in sync! No new records to add.")
        return True
    
    # Preview what will be added
    if a_to_add:
        logger.info("\n➕ New A/AAAA records:")
        for record in a_to_add[:5]:
            logger.info(f"      {record['domain']} -> {record['ip']}")
        if len(a_to_add) > 5:
            logger.info(f"      ... and {len(a_to_add) - 5} more")
    
    if cname_to_add:
        logger.info("\n➕ New CNAME records:")
        for record in cname_to_add[:5]:
            logger.info(f"      {record['domain']} -> {record['target']}")
        if len(cname_to_add) > 5:
            logger.info(f"      ... and {len(cname_to_add) - 5} more")
    
    # Auto-approve or ask
    if AUTO_APPROVE:
        logger.info("\n🤖 Auto-approve mode: Adding all new records")
        proceed = True
    else:
        response = input(f"\n🔄 Add {len(a_to_add)} A records and {len(cname_to_add)} CNAME records? (y/N): ")
        proceed = response.lower() == 'y'
    
    if not proceed:
        logger.info("❌ Sync cancelled")
        return False
    
    # Add A records
    success_a = True
    added_a = 0
    duplicate_a = 0
    failed_a = 0
    
    if a_to_add:
        logger.info("\n📤 Adding A/AAAA records...")
        for record in a_to_add:
            success, status = pihole_session.add_a_record(record['ip'], record['domain'], ignore_duplicates=True)
            if success:
                if status == 'added':
                    added_a += 1
                elif status == 'exists':
                    duplicate_a += 1
            else:
                failed_a += 1
                success_a = False
    
    # Add CNAME records
    success_cname = True
    added_cname = 0
    duplicate_cname = 0
    failed_cname = 0
    
    if cname_to_add:
        logger.info("\n📤 Adding CNAME records...")
        for record in cname_to_add:
            success, status = pihole_session.add_cname_record(record['domain'], record['target'], ignore_duplicates=True)
            if success:
                if status == 'added':
                    added_cname += 1
                elif status == 'exists':
                    duplicate_cname += 1
            else:
                failed_cname += 1
                success_cname = False
    
    elapsed_time = time.time() - start_time
    
    # Final summary
    logger.info("\n" + "=" * 50)
    logger.info("📋 FINAL SYNC REPORT")
    logger.info("=" * 50)
    
    if added_a > 0 or added_cname > 0:
        logger.info(f"✅ Added: {added_a} A records, {added_cname} CNAME records")
    
    if duplicate_a > 0 or duplicate_cname > 0:
        logger.info(f"⏭️  Duplicates ignored: {duplicate_a} A records, {duplicate_cname} CNAME records")
    
    if failed_a > 0 or failed_cname > 0:
        logger.info(f"❌ Failed: {failed_a} A records, {failed_cname} CNAME records")
    
    if success_a and success_cname:
        logger.info(f"\n✅ Sync completed successfully in {elapsed_time:.2f} seconds!")
    else:
        logger.info(f"\n⚠️  Sync completed with some errors in {elapsed_time:.2f} seconds")
    
    # Show final counts
    final_a, final_cname = pihole_session.get_all_records()
    logger.info(f"📊 Pi-hole now has {len(final_a)} A records and {len(final_cname)} CNAME records")
    
    return success_a and success_cname

# -----------------------------
# Main
# -----------------------------
def main():
    logger.info("=" * 50)
    logger.info("Pi-hole and AdGuard DNS Sync")
    logger.info("=" * 50)
    
    if AUTO_APPROVE:
        logger.info("Auto-approve mode enabled (-y)")
    
    # Validate environment variables
    required_vars = {
        "ADGUARD_URL": ADGUARD_URL,
        "ADGUARD_USER": ADGUARD_USER,
        "ADGUARD_PASS": ADGUARD_PASS,
        "PIHOLE_URL": PIHOLE_URL,
        "PIHOLE_PASS": PIHOLE_PASS
    }
    
    missing = [var for var, value in required_vars.items() if not value]
    if missing:
        logger.error(f"Missing environment variables: {', '.join(missing)}")
        logger.error("Please check your .env file")
        sys.exit(1)
    
    logger.info(f"📡 Pi-hole URL: {PIHOLE_URL}")
    logger.info(f"📡 AdGuard URL: {ADGUARD_URL}")
    
    try:
        # Fetch AdGuard rewrites first (doesn't need Pi-hole session)
        adguard_records = fetch_adguard_rewrites()
        
        # Use context manager for Pi-hole session (auto login/logout)
        with PiHoleSession(PIHOLE_URL, PIHOLE_PASS) as pihole:
            sync_records(adguard_records, pihole)
        
    except KeyboardInterrupt:
        logger.info("\n⚠️  Sync interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()