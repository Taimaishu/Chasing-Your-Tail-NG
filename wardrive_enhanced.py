#!/usr/bin/env python3
"""
Enhanced Wardriving Dashboard with Surveillance Detection
Integrates WiGLE API, device tracking, and "Following Me" detection
"""

from flask import Flask, render_template_string, jsonify, request
import subprocess
import json
import os
import time
import glob
import sqlite3
import requests
import base64
from datetime import datetime
from collections import defaultdict, Counter

# Simple MAC OUI lookup
def get_vendor_from_mac(mac):
    """Simple MAC vendor lookup from common OUIs"""
    oui_map = {
        '00:1A:7D': 'Broadcom', '00:50:F2': 'Microsoft', '00:15:5D': 'Microsoft',
        '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM', 'DC:A6:32': 'Raspberry Pi',
        'B8:27:EB': 'Raspberry Pi', 'E4:5F:01': 'Raspberry Pi', '28:CD:C1': 'Raspberry Pi',
        '00:1B:63': 'Apple', '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0A:27': 'Apple',
        '00:0A:95': 'Apple', '00:0D:93': 'Apple', '00:10:FA': 'Apple', '00:11:24': 'Apple',
        '00:14:51': 'Apple', '00:16:CB': 'Apple', '00:17:F2': 'Apple', '00:19:E3': 'Apple',
        '00:1C:B3': 'Apple', '00:1D:4F': 'Apple', '00:1E:52': 'Apple', '00:1F:5B': 'Apple',
        '00:1F:F3': 'Apple', '00:21:E9': 'Apple', '00:22:41': 'Apple', '00:23:12': 'Apple',
        '00:23:32': 'Apple', '00:23:6C': 'Apple', '00:23:DF': 'Apple', '00:24:36': 'Apple',
        '00:25:00': 'Apple', '00:25:4B': 'Apple', '00:25:BC': 'Apple', '00:26:08': 'Apple',
        '00:26:B0': 'Apple', '00:26:BB': 'Apple', 'FC:E9:98': 'Apple', 'F0:99:BF': 'Apple',
        '00:0C:29': 'VMware', '00:50:56': 'VMware', '00:05:69': 'VMware',
        '00:1C:42': 'Parallels', '00:1C:14': 'Dell', 'D4:BE:D9': 'Dell', '18:03:73': 'Dell',
        '00:14:22': 'Dell', '00:1D:09': 'Dell', '00:21:70': 'Dell', '00:21:9B': 'Dell',
        '00:24:E8': 'Dell', '00:25:64': 'Dell', '00:26:B9': 'Dell',
        '00:1B:21': 'Intel', '00:1E:67': 'Intel', '00:21:6A': 'Intel', '00:24:D7': 'Intel',
        '00:27:0E': 'Intel', '3C:A9:F4': 'Intel', '7C:7A:91': 'Intel',
        '00:23:AE': 'LG', '00:1E:75': 'LG', 'B0:37:95': 'LG',
        '00:1D:09': 'Samsung', '00:12:FB': 'Samsung', '00:15:B9': 'Samsung', '00:16:32': 'Samsung',
        '00:17:C9': 'Samsung', '00:18:AF': 'Samsung', '00:1A:8A': 'Samsung', '00:1B:98': 'Samsung',
        '00:1C:43': 'Samsung', '00:1D:25': 'Samsung', '00:1E:7D': 'Samsung', '00:1F:CD': 'Samsung',
        '00:21:4C': 'Samsung', '00:23:39': 'Samsung', '00:23:D6': 'Samsung', '00:24:54': 'Samsung',
        '00:25:38': 'Samsung', '00:26:37': 'Samsung', '00:12:47': 'Google', '54:60:09': 'Google',
        'F4:F5:D8': 'Google', '3C:5A:B4': 'Google', 'DC:EF:CA': 'Google',
        '48:F1:7F': 'Amazon', '74:75:48': 'Amazon', '00:FC:8B': 'Amazon',
        '18:74:2E': 'OnePlus', 'AC:37:43': 'OnePlus', '48:4B:AA': 'Xiaomi',
        '34:CE:00': 'Xiaomi', '64:09:80': 'Xiaomi', '78:02:F8': 'Xiaomi',
        '00:26:BB': 'TP-Link', '00:27:19': 'TP-Link', 'F4:EC:38': 'TP-Link',
        '00:1F:3C': 'Netgear', '00:24:B2': 'Netgear', 'A0:63:91': 'Netgear',
        'E0:C2:50': 'Comcast', '70:F2:20': 'Comcast'
    }

    mac_upper = mac.upper()
    oui = ':'.join(mac_upper.split(':')[:3])
    return oui_map.get(oui, None)

app = Flask(__name__)

# Load WiGLE credentials
WIGLE_USER = "taimaishuz"
WIGLE_PASS = "Ones&zer0s"
WIGLE_API_URL = "https://api.wigle.net/api/v2/network/search"

# Device tracking storage
device_history = defaultdict(list)  # MAC -> [(timestamp, location, signal)]
persistent_devices = set()  # MACs seen multiple times
ssid_cache = {}  # SSID -> WiGLE location data

# Blacklist/Whitelist paths
BLACKLIST_PATH = '/home/taimaishu/Chasing-Your-Tail-NG/ignore_lists/mac_list.json'
WHITELIST_PATH = '/home/taimaishu/Chasing-Your-Tail-NG/ignore_lists/whitelist.json'

def load_list(filepath):
    """Load MAC list from JSON file"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return set(json.load(f))
    except Exception:
        pass
    return set()

def save_list(filepath, mac_list):
    """Save MAC list to JSON file"""
    try:
        with open(filepath, 'w') as f:
            json.dump(sorted(list(mac_list)), f, indent=2)
        return True
    except Exception:
        return False

def get_blacklist():
    """Get current blacklist"""
    return load_list(BLACKLIST_PATH)

def get_whitelist():
    """Get current whitelist"""
    return load_list(WHITELIST_PATH)

def get_wigle_auth():
    """Get WiGLE API authentication header"""
    token = base64.b64encode(f"{WIGLE_USER}:{WIGLE_PASS}".encode()).decode()
    return {'Authorization': f'Basic {token}'}

def query_wigle_ssid(ssid):
    """Query WiGLE for SSID location"""
    if ssid in ssid_cache:
        return ssid_cache[ssid]

    try:
        response = requests.get(
            WIGLE_API_URL,
            params={'ssid': ssid},
            headers=get_wigle_auth(),
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('results'):
                result = data['results'][0]
                location = {
                    'lat': result.get('trilat'),
                    'lon': result.get('trilong'),
                    'city': result.get('city', 'Unknown'),
                    'country': result.get('country', 'Unknown'),
                    'lastupdt': result.get('lastupdt', 'Unknown')
                }
                ssid_cache[ssid] = location
                return location
    except Exception:
        pass
    return None

def analyze_kismet_db(db_path, filter_blacklist=True):
    """Analyze Kismet database for surveillance patterns"""
    devices = []
    following_devices = []
    blacklist = get_blacklist() if filter_blacklist else set()

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get all devices with their appearance times
        cursor.execute("""
            SELECT
                devmac,
                type,
                first_time,
                last_time,
                bytes_data,
                device
            FROM devices
            WHERE type LIKE '%Wi-Fi%' OR type LIKE '%Bluetooth%' OR type LIKE '%BTLE%' OR type LIKE '%BT%'
            ORDER BY last_time DESC
            LIMIT 1000
        """)

        rows = cursor.fetchall()
        current_time = time.time()

        for row in rows:
            mac, dev_type, first_seen, last_seen, bytes_data, device_json = row

            # Skip blacklisted devices
            if filter_blacklist and mac in blacklist:
                continue

            # Track device history
            duration = last_seen - first_seen
            device_history[mac].append({
                'first_seen': first_seen,
                'last_seen': last_seen,
                'duration': duration,
                'packets': bytes_data  # Using bytes_data as packet count approximation
            })

            # Parse device JSON for detailed info
            ssids = []
            manufacturer = 'Unknown'
            device_name = ''
            signal_dbm = 0
            channel = ''
            encryption = 'Unknown'
            frequency = 0
            device_class = ''

            try:
                if device_json:
                    dev_data = json.loads(device_json)

                    # Base device info
                    manufacturer = dev_data.get('kismet.device.base.manuf', 'Unknown')

                    # Try OUI lookup if Kismet didn't provide manufacturer
                    if manufacturer == 'Unknown' or not manufacturer:
                        vendor = get_vendor_from_mac(mac)
                        if vendor:
                            manufacturer = vendor

                    device_name = dev_data.get('kismet.device.base.name', '')
                    if not device_name:
                        device_name = dev_data.get('kismet.device.base.commonname', '')

                    # Signal info
                    signal_data = dev_data.get('kismet.device.base.signal', {})
                    if isinstance(signal_data, dict):
                        signal_dbm = signal_data.get('kismet.common.signal.last_signal', 0)

                    # Channel and frequency
                    channel = dev_data.get('kismet.device.base.channel', '')
                    frequency = dev_data.get('kismet.device.base.frequency', 0)

                    # Encryption
                    encryption = dev_data.get('kismet.device.base.crypt', 'None')

                    # WiFi specific
                    if 'dot11.device' in dev_data:
                        wifi_data = dev_data['dot11.device']
                        probed = wifi_data.get('dot11.device.probed_ssid_map', {})
                        ssids = list(probed.keys())[:5]

                        # Get advertised SSIDs too
                        advertised = wifi_data.get('dot11.device.advertised_ssid_map', {})
                        if advertised and not ssids:
                            ssids = [s.get('dot11.advertisedssid.ssid', '') for s in advertised.values()][:5]

                    # Bluetooth specific
                    if 'bluetooth.device' in dev_data:
                        bt_data = dev_data['bluetooth.device']
                        device_name = bt_data.get('bluetooth.device.name', device_name)
                        device_class = bt_data.get('bluetooth.device.class', '')

            except:
                pass

            # Persistence detection (seen multiple times)
            appearances = len(device_history[mac])
            is_persistent = appearances >= 3 or duration > 300  # 3+ times or 5+ mins

            device_info = {
                'mac': mac,
                'type': dev_type,
                'first_seen': datetime.fromtimestamp(first_seen).strftime('%H:%M:%S'),
                'last_seen': datetime.fromtimestamp(last_seen).strftime('%H:%M:%S'),
                'duration': int(duration),
                'packets': bytes_data,
                'appearances': appearances,
                'persistent': is_persistent,
                'ssids': ssids,
                'age_minutes': int((current_time - last_seen) / 60),
                # Enhanced info
                'manufacturer': manufacturer,
                'name': device_name,
                'signal': signal_dbm,
                'channel': channel,
                'encryption': encryption,
                'frequency': frequency,
                'device_class': device_class
            }

            devices.append(device_info)

            # Flag as potential follower
            if is_persistent and device_info['age_minutes'] < 10:
                persistent_devices.add(mac)
                following_devices.append(device_info)

        conn.close()

        return {
            'total_devices': len(devices),
            'all_devices': devices[:50],  # Top 50 most recent
            'following': following_devices,
            'persistent_count': len(persistent_devices)
        }
    except Exception as e:
        return {
            'total_devices': 0,
            'all_devices': [],
            'following': [],
            'persistent_count': 0,
            'error': str(e)
        }

# Enhanced HTML Dashboard
ENHANCED_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Surveillance Detection Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        :root {
            --primary: #6366f1;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --dark: #0f172a;
            --card: #1e293b;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--dark);
            color: #f1f5f9;
            font-size: 13px;
            overflow-x: hidden;
        }

        .container {
            width: 100vw;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
            padding: 12px 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo h1 {
            font-size: 18px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-badge {
            background: rgba(255,255,255,0.2);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .alert-badge.warning { background: var(--warning); color: white; animation: pulse 1.5s infinite; }
        .alert-badge.safe { background: var(--success); color: white; }

        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }

        /* Tabs */
        .tabs {
            display: flex;
            background: #1e293b;
            border-bottom: 2px solid #334155;
        }

        .tab {
            flex: 1;
            padding: 15px;
            text-align: center;
            cursor: pointer;
            font-weight: 700;
            font-size: 13px;
            transition: all 0.3s;
            border-bottom: 3px solid transparent;
        }

        .tab:hover { background: #334155; }
        .tab.active { background: #334155; border-bottom-color: var(--primary); color: var(--primary); }

        /* Tab Content */
        .tab-content {
            display: none;
            flex: 1;
            overflow-y: auto;
            padding: 15px;
        }

        .tab-content.active { display: block; }

        /* Cards */
        .card {
            background: var(--card);
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 15px;
            border: 1px solid #334155;
        }

        .card-header {
            font-size: 14px;
            font-weight: 700;
            margin-bottom: 12px;
            padding-bottom: 10px;
            border-bottom: 1px solid #334155;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .badge {
            font-size: 10px;
            padding: 4px 8px;
            border-radius: 10px;
            font-weight: 700;
        }

        .badge-danger { background: var(--danger); color: white; }
        .badge-warning { background: var(--warning); color: white; }
        .badge-success { background: var(--success); color: white; }
        .badge-primary { background: var(--primary); color: white; }

        /* Device List */
        .device-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .device-item {
            background: rgba(100,116,139,0.1);
            border-left: 3px solid #475569;
            padding: 12px;
            border-radius: 8px;
            transition: all 0.2s;
        }

        .device-item:hover { background: rgba(100,116,139,0.2); }
        .device-item.following { border-left-color: var(--danger); background: rgba(239,68,68,0.1); }
        .device-item.persistent { border-left-color: var(--warning); background: rgba(245,158,11,0.1); }

        .device-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
        }

        .device-mac {
            font-family: 'Courier New', monospace;
            font-weight: 700;
            font-size: 13px;
            word-break: break-all;
        }

        .device-meta {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
            font-size: 11px;
            color: #94a3b8;
        }

        .device-ssids {
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid #334155;
            font-size: 11px;
        }

        .ssid-tag {
            display: inline-block;
            background: rgba(99,102,241,0.2);
            color: #a5b4fc;
            padding: 3px 8px;
            border-radius: 6px;
            margin: 2px;
            font-size: 10px;
        }

        .wigle-location {
            margin-top: 6px;
            padding: 6px;
            background: rgba(59,130,246,0.1);
            border-radius: 6px;
            font-size: 10px;
            color: #60a5fa;
        }

        /* Control Buttons */
        .controls {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-bottom: 15px;
        }

        .btn {
            padding: 15px;
            border: none;
            border-radius: 10px;
            font-weight: 700;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.2s;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn:active { transform: scale(0.96); }
        .btn-start { background: linear-gradient(135deg, #10b981, #059669); }
        .btn-stop { background: linear-gradient(135deg, #ef4444, #dc2626); }
        .btn-scan { background: linear-gradient(135deg, #f59e0b, #d97706); }
        .btn-primary { background: linear-gradient(135deg, #3b82f6, #2563eb); }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-bottom: 15px;
        }

        .stat-box {
            background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.1));
            padding: 12px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid rgba(99,102,241,0.2);
        }

        .stat-number {
            font-size: 24px;
            font-weight: 800;
            background: linear-gradient(135deg, #60a5fa, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .stat-label {
            font-size: 10px;
            color: #94a3b8;
            text-transform: uppercase;
            margin-top: 4px;
        }

        /* GPS Display */
        .gps-display {
            background: linear-gradient(135deg, rgba(59,130,246,0.1), rgba(99,102,241,0.1));
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            border: 1px solid rgba(59,130,246,0.2);
        }

        .gps-coords {
            font-size: 16px;
            font-weight: 700;
            font-family: monospace;
            color: #60a5fa;
            margin: 8px 0;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #64748b;
        }

        .empty-icon { font-size: 48px; margin-bottom: 12px; }

        /* Loading */
        .loading { text-align: center; padding: 20px; color: #64748b; }

        /* Map */
        #map { height: 100%; width: 100%; border-radius: 10px; }
        .map-container { height: calc(100vh - 200px); padding: 0; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <h1>🚨 Surveillance Detection System</h1>
                </div>
                <div class="alert-badge" id="alertBadge">
                    <span id="alertText">SAFE</span>
                </div>
            </div>
        </div>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab active" onclick="showTab('following')">
                🎯 Following Me (<span id="followingCount">0</span>)
            </div>
            <div class="tab" onclick="showTab('devices')">
                📡 All Devices (<span id="devicesCount">0</span>)
            </div>
            <div class="tab" onclick="showTab('map')">
                🗺️ Map
            </div>
            <div class="tab" onclick="showTab('blacklist')">
                🚫 Blacklist (<span id="blacklistCount">0</span>)
            </div>
            <div class="tab" onclick="showTab('control')">
                🎮 Control
            </div>
        </div>

        <!-- Tab Content -->
        <div class="tab-content active" id="tab-following">
            <div class="card">
                <div class="card-header">
                    🚨 Devices Following You
                    <span class="badge badge-danger" id="threatLevel">ANALYZING</span>
                </div>
                <div id="followingDevices" class="device-list">
                    <div class="loading">Analyzing surveillance patterns...</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">🛰️ Current Location</div>
                <div class="gps-display">
                    <div class="gps-coords" id="gpsCoords">---.------°, ---.------°</div>
                    <div style="font-size: 11px; color: #94a3b8;">
                        <div id="gpsDetails">Satellites: -- | Alt: --- m</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="tab-content" id="tab-devices">
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-number" id="statTotal">0</div>
                    <div class="stat-label">Total</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="statPersistent">0</div>
                    <div class="stat-label">Persistent</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="statRecent">0</div>
                    <div class="stat-label">Recent</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    📡 All Detected Devices
                    <span class="badge badge-primary" id="dbStatus">SCANNING</span>
                </div>
                <div id="allDevices" class="device-list">
                    <div class="loading">Loading device data...</div>
                </div>
            </div>
        </div>

        <div class="tab-content" id="tab-map">
            <div class="controls" style="grid-template-columns: repeat(3, 1fr);">
                <button class="btn btn-primary" onclick="setManualLocation()">
                    📍 Set My Location
                </button>
                <button class="btn btn-scan" onclick="loadWigleData()">
                    🌍 Load WiGLE Networks
                </button>
                <button class="btn btn-scan" onclick="setDemoLocation()">
                    🎮 Demo Mode
                </button>
                <button class="btn btn-primary" onclick="trackDevice('demo/2D:32:A5:0B:D0:7D')">
                    🗺️ Demo Track
                </button>
                <button class="btn btn-primary" onclick="window.open('https://wigle.net/', '_blank')">
                    🔗 Open WiGLE.net
                </button>
            </div>

            <div class="card map-container">
                <div id="map"></div>
            </div>

            <div class="card">
                <div class="card-header">📍 Location Info</div>
                <div class="gps-display">
                    <div class="gps-coords" id="mapGpsCoords">---.------°, ---.------°</div>
                    <div style="font-size: 11px; color: #94a3b8;">
                        <div id="mapGpsDetails">Click "Use Demo Location" or wait for GPS fix</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="tab-content" id="tab-blacklist">
            <div class="controls">
                <button class="btn btn-primary" onclick="autoBlacklist()">
                    🤖 Auto-Blacklist Current Devices
                </button>
                <button class="btn btn-stop" onclick="clearBlacklist()">
                    🗑️ Clear Blacklist
                </button>
            </div>

            <div class="card">
                <div class="card-header">
                    🚫 Blacklisted Devices
                    <span class="badge badge-danger" id="blacklistTotal">0</span>
                </div>
                <div id="blacklistDevices" class="device-list">
                    <div class="loading">Loading blacklist...</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">ℹ️ About Blacklist</div>
                <div style="padding: 10px; font-size: 11px; color: #94a3b8; line-height: 1.6;">
                    <p>• Blacklisted devices are <strong>hidden</strong> from surveillance detection</p>
                    <p>• Use this to filter out home/office/neighbor devices</p>
                    <p>• Auto-blacklist: Adds all currently visible devices</p>
                    <p>• Click device MAC to remove from blacklist</p>
                </div>
            </div>
        </div>

        <div class="tab-content" id="tab-control">
            <div class="controls">
                <button class="btn btn-start" id="btnStart" onclick="startWardriving()">
                    ▶️ Start
                </button>
                <button class="btn btn-stop" id="btnStop" onclick="stopWardriving()" disabled>
                    ⏹️ Stop
                </button>
                <button class="btn btn-scan" onclick="scanNow()">
                    🔍 Scan Now
                </button>
                <button class="btn btn-primary" onclick="refreshAll()">
                    🔄 Refresh
                </button>
            </div>

            <div class="card">
                <div class="card-header">⚙️ System Status</div>
                <div id="systemStatus" class="device-list">
                    <div class="loading">Loading...</div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">📊 Capture Statistics</div>
                <div class="stats-grid">
                    <div class="stat-box">
                        <div class="stat-number" id="statNetworks">0</div>
                        <div class="stat-label">Networks</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" id="statPackets">0</div>
                        <div class="stat-label">Packets</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number" id="statUptime">00:00</div>
                        <div class="stat-label">Uptime</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let startTime = null;
        let currentTab = 'following';
        let map = null;
        let deviceMarkers = {};
        let devicePaths = {};
        let currentLocation = null;

        function initMap() {
            if (map) return;

            // 1521 N Waverly St, Washington, Utah 84780 (EXACT)
            const defaultLat = 37.1518108;
            const defaultLon = -113.5291983;

            map = L.map('map').setView([defaultLat, defaultLon], 13);

            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© OpenStreetMap contributors',
                maxZoom: 19
            }).addTo(map);

            // Add current location marker
            currentLocation = L.marker([defaultLat, defaultLon], {
                icon: L.icon({
                    iconUrl: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSI4IiBmaWxsPSIjMDBmZjQxIi8+PGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iNCIgZmlsbD0iI2ZmZmZmZiIvPjwvc3ZnPg==',
                    iconSize: [24, 24],
                    iconAnchor: [12, 12]
                })
            }).addTo(map).bindPopup('📍 Your Location');
        }

        function updateMapLocation(lat, lon) {
            if (!map) initMap();

            map.setView([lat, lon], 15);
            if (currentLocation) {
                currentLocation.setLatLng([lat, lon]);
            }

            document.getElementById('mapGpsCoords').textContent =
                `${lat.toFixed(6)}°N, ${Math.abs(lon).toFixed(6)}°W`;
            document.getElementById('mapGpsDetails').textContent =
                `1521 N Waverly St, Washington, UT | Click markers for device info`;

            // Also update main GPS display on Following tab
            document.getElementById('gpsCoords').textContent =
                `${lat.toFixed(6)}°N, ${Math.abs(lon).toFixed(6)}°W`;
            document.getElementById('gpsDetails').textContent =
                `1521 N Waverly St, Washington, UT 84780`;
        }

        function setManualLocation() {
            const lat = prompt('Enter your Latitude (e.g., 37.1518108):', '37.1518108');
            const lon = prompt('Enter your Longitude (e.g., -113.5291983):', '-113.5291983');

            if (lat && lon) {
                const latitude = parseFloat(lat);
                const longitude = parseFloat(lon);

                if (!isNaN(latitude) && !isNaN(longitude)) {
                    updateMapLocation(latitude, longitude);
                    alert(`✓ Location set to ${latitude.toFixed(6)}°, ${longitude.toFixed(6)}°`);
                } else {
                    alert('✗ Invalid coordinates');
                }
            }
        }

        function setDemoLocation() {
            // 1521 N Waverly St, Washington, Utah (EXACT)
            const lat = 37.1518108 + (Math.random() - 0.5) * 0.01;
            const lon = -113.5291983 + (Math.random() - 0.5) * 0.01;
            updateMapLocation(lat, lon);

            // Add some demo device markers
            addDemoDevices(lat, lon);
        }

        function addDemoDevices(centerLat, centerLon) {
            const demoDevices = [
                {name: 'iPhone 12 Pro', mac: '00:1B:63:84:45:E6', type: 'following', offset: [0.002, 0.003], manufacturer: 'Apple'},
                {name: 'Samsung Galaxy S21', mac: '34:CE:00:12:34:56', type: 'device', offset: [-0.001, 0.002], manufacturer: 'Samsung'},
                {name: 'Tesla Model 3 WiFi', mac: 'B2:D8:88:F3:38:6C', type: 'following', offset: [0.003, -0.001], manufacturer: 'Tesla'},
                {name: 'Comcast Router XB7', mac: 'E0:C2:50:22:9D:5F', type: 'device', offset: [-0.002, -0.002], manufacturer: 'Comcast'},
                {name: 'Apple Watch Series 6', mac: '00:26:BB:12:34:78', type: 'following', offset: [0.0015, 0.0025], manufacturer: 'Apple'}
            ];

            // Clear existing markers first
            Object.values(deviceMarkers).forEach(m => map.removeLayer(m));
            deviceMarkers = {};

            demoDevices.forEach(dev => {
                const lat = centerLat + dev.offset[0];
                const lon = centerLon + dev.offset[1];
                const color = dev.type === 'following' ? '#ef4444' : '#6366f1';

                const marker = L.circleMarker([lat, lon], {
                    radius: 10,
                    fillColor: color,
                    color: '#fff',
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 0.8
                }).addTo(map);

                marker.bindPopup(`
                    <div style="min-width: 200px;">
                        <strong style="font-size: 14px;">${dev.name}</strong><br>
                        <hr style="margin: 5px 0;">
                        📱 ${dev.manufacturer}<br>
                        🔖 MAC: ${dev.mac}<br>
                        ${dev.type === 'following' ? '🚨 <strong style="color: #ef4444;">FOLLOWING YOU</strong>' : '📡 Nearby Device'}<br>
                        📍 ${lat.toFixed(6)}°N, ${Math.abs(lon).toFixed(6)}°W
                    </div>
                `);

                deviceMarkers[dev.mac] = marker;
            });
        }

        function centerMap() {
            if (!map) return;
            if (currentLocation) {
                map.setView(currentLocation.getLatLng(), 15);
            }
        }

        function trackDeviceAndShowMap(mac, event) {
            // Switch to map tab
            switchTab('map');

            // Initialize map if needed
            if (!map) {
                initMap();
            }

            // Track the device
            trackDevice(mac);
        }

        function trackDevice(mac) {
            fetch(`/api/device/track/${mac}`)
                .then(r => r.json())
                .then(data => {
                    if (data.locations && data.locations.length > 0) {
                        // Draw path
                        const latlngs = data.locations.map(loc => [loc.lat, loc.lon]);

                        // Remove old path if exists
                        if (devicePaths[mac]) {
                            map.removeLayer(devicePaths[mac]);
                        }

                        // Draw new path
                        devicePaths[mac] = L.polyline(latlngs, {
                            color: '#ef4444',
                            weight: 3,
                            opacity: 0.7,
                            dashArray: '10, 5'
                        }).addTo(map);

                        // Fit map to show full path
                        map.fitBounds(devicePaths[mac].getBounds());

                        alert(`✓ Showing movement for ${mac}\nLocations: ${data.locations.length}`);
                    } else {
                        alert('No GPS data available for this device yet');
                    }
                });
        }

        function loadWigleData() {
            if (!map || !currentLocation) {
                alert('Set a location first');
                return;
            }

            const latlng = currentLocation.getLatLng();

            fetch(`/api/wigle/nearby?lat=${latlng.lat}&lon=${latlng.lng}`)
                .then(r => r.json())
                .then(data => {
                    if (data.networks) {
                        data.networks.forEach(net => {
                            const color = net.encryption.includes('WPA') ? '#10b981' : '#ef4444';

                            const marker = L.circleMarker([net.lat, net.lon], {
                                radius: 6,
                                fillColor: color,
                                color: '#fff',
                                weight: 1,
                                opacity: 0.8,
                                fillOpacity: 0.6
                            }).addTo(map);

                            marker.bindPopup(`
                                <strong>${net.ssid || 'Hidden'}</strong><br>
                                MAC: ${net.mac}<br>
                                🔒 ${net.encryption}<br>
                                📡 Ch ${net.channel}<br>
                                🕐 Last: ${net.lastupdt}<br>
                                <a href="https://wigle.net/search?netid=${net.mac}" target="_blank">View on WiGLE</a>
                            `);
                        });

                        alert(`✓ Loaded ${data.count} networks from WiGLE`);
                    } else {
                        alert('✗ Error loading WiGLE data: ' + (data.error || 'Unknown'));
                    }
                });
        }

        function showTab(tabName) {
            // Update tabs
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

            event.target.closest('.tab').classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');
            currentTab = tabName;

            // Load tab-specific data
            if (tabName === 'blacklist') {
                updateBlacklist();
            } else if (tabName === 'map') {
                setTimeout(() => {
                    initMap();
                    if (map) map.invalidateSize();
                }, 100);
            }
        }

        function updateBlacklist() {
            fetch('/api/blacklist')
                .then(r => r.json())
                .then(data => {
                    const blacklist = data.blacklist || [];
                    document.getElementById('blacklistCount').textContent = blacklist.length;
                    document.getElementById('blacklistTotal').textContent = blacklist.length;

                    const listHtml = blacklist.length > 0 ?
                        blacklist.map(mac => `
                            <div class="device-item" style="cursor: pointer;" onclick="removeFromBlacklist('${mac}')">
                                <div class="device-header">
                                    <span class="device-mac">${mac}</span>
                                    <span class="badge badge-danger">🗑️ Click to Remove</span>
                                </div>
                            </div>
                        `).join('') :
                        '<div class="empty-state"><div class="empty-icon">✅</div><div>Blacklist is empty</div></div>';

                    document.getElementById('blacklistDevices').innerHTML = listHtml;
                });
        }

        function updateStatus() {
            // Get basic status
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    // GPS
                    if (data.gps.fix) {
                        document.getElementById('gpsCoords').textContent =
                            `${data.gps.lat.toFixed(6)}°, ${data.gps.lon.toFixed(6)}°`;
                        document.getElementById('gpsDetails').textContent =
                            `Satellites: ${data.gps.satellites} | Alt: ${data.gps.alt.toFixed(1)} m`;

                        // Update map location
                        if (currentTab === 'map') {
                            updateMapLocation(data.gps.lat, data.gps.lon);
                        }
                    }

                    // Stats
                    document.getElementById('statNetworks').textContent = data.stats.networks;
                    document.getElementById('statPackets').textContent = (data.stats.packets || 0).toLocaleString();

                    // Button states
                    const running = data.system.Kismet === 'Running';
                    document.getElementById('btnStart').disabled = running;
                    document.getElementById('btnStop').disabled = !running;

                    // Uptime
                    if (running) {
                        if (!startTime) startTime = Date.now();
                        const uptime = Math.floor((Date.now() - startTime) / 1000);
                        const mins = Math.floor(uptime / 60);
                        const secs = uptime % 60;
                        document.getElementById('statUptime').textContent =
                            `${String(mins).padStart(2,'0')}:${String(secs).padStart(2,'0')}`;
                    } else {
                        startTime = null;
                        document.getElementById('statUptime').textContent = '00:00';
                    }

                    // System status
                    let statusHtml = '';
                    for (const [key, value] of Object.entries(data.system)) {
                        const isRunning = value.includes('Running') || value.includes('Monitor');
                        statusHtml += `
                            <div class="device-item ${isRunning ? 'persistent' : ''}">
                                <div class="device-header">
                                    <span>${key}</span>
                                    <span class="badge badge-${isRunning ? 'success' : 'danger'}">${value}</span>
                                </div>
                            </div>`;
                    }
                    document.getElementById('systemStatus').innerHTML = statusHtml;
                });

            // Get surveillance analysis
            fetch('/api/surveillance')
                .then(r => r.json())
                .then(data => {
                    // Update counts
                    document.getElementById('followingCount').textContent = data.following.length;
                    document.getElementById('devicesCount').textContent = data.total_devices;
                    document.getElementById('statTotal').textContent = data.total_devices;
                    document.getElementById('statPersistent').textContent = data.persistent_count;

                    // Alert badge
                    const alertBadge = document.getElementById('alertBadge');
                    const alertText = document.getElementById('alertText');
                    if (data.following.length > 0) {
                        alertBadge.className = 'alert-badge warning';
                        alertText.textContent = `${data.following.length} FOLLOWING`;
                    } else {
                        alertBadge.className = 'alert-badge safe';
                        alertText.textContent = 'SAFE';
                    }

                    // Render following devices
                    const followingHtml = data.following.length > 0 ?
                        data.following.map(dev => renderDevice(dev, true)).join('') :
                        '<div class="empty-state"><div class="empty-icon">✅</div><div>No suspicious devices detected</div><div style="font-size: 11px; margin-top: 8px;">You appear to be safe</div></div>';
                    document.getElementById('followingDevices').innerHTML = followingHtml;

                    // Render all devices
                    const allHtml = data.all_devices.length > 0 ?
                        data.all_devices.map(dev => renderDevice(dev, false)).join('') :
                        '<div class="empty-state"><div class="empty-icon">📡</div><div>No devices detected yet</div></div>';
                    document.getElementById('allDevices').innerHTML = allHtml;

                    // Threat level
                    const threatLevel = document.getElementById('threatLevel');
                    if (data.following.length >= 5) {
                        threatLevel.textContent = 'HIGH THREAT';
                        threatLevel.className = 'badge badge-danger';
                    } else if (data.following.length >= 2) {
                        threatLevel.textContent = 'MODERATE';
                        threatLevel.className = 'badge badge-warning';
                    } else {
                        threatLevel.textContent = 'SAFE';
                        threatLevel.className = 'badge badge-success';
                    }

                    // DB status
                    document.getElementById('dbStatus').textContent = data.error ? 'ERROR' : 'ACTIVE';
                });
        }

        function renderDevice(dev, isFollowing) {
            // Build device title
            let deviceTitle = dev.mac;
            if (dev.name && dev.name !== '') {
                deviceTitle = `${dev.name} (${dev.mac})`;
            }

            // Signal strength indicator
            let signalColor = '#64748b';
            let signalText = 'Unknown';
            if (dev.signal < 0) {
                signalText = `${dev.signal} dBm`;
                if (dev.signal > -50) { signalColor = '#10b981'; } // Excellent
                else if (dev.signal > -70) { signalColor = '#f59e0b'; } // Good
                else { signalColor = '#ef4444'; } // Weak
            }

            let html = `
                <div class="device-item ${isFollowing ? 'following' : (dev.persistent ? 'persistent' : '')}">
                    <div class="device-header">
                        <div style="flex: 1;">
                            <div class="device-mac" style="font-size: 11px; margin-bottom: 4px;">${deviceTitle}</div>
                            ${dev.manufacturer !== 'Unknown' ? `<div style="font-size: 10px; color: #94a3b8;">📱 ${dev.manufacturer}</div>` : ''}
                        </div>
                        <div>
                            <button class="btn btn-primary" style="padding: 4px 8px; font-size: 10px; margin-right: 5px;" onclick="trackDeviceAndShowMap('${dev.mac}', event)">🗺️ Track</button>
                            <button class="btn btn-stop" style="padding: 4px 8px; font-size: 10px; margin-right: 5px;" onclick="addToBlacklistSingle('${dev.mac}', event)">🚫 Blacklist</button>
                            <span class="badge badge-${dev.persistent ? 'warning' : 'primary'}">${dev.type}</span>
                        </div>
                    </div>

                    <div class="device-meta" style="grid-template-columns: repeat(4, 1fr);">
                        <div>👁️ Seen: ${dev.appearances}x</div>
                        <div>⏱️ ${Math.floor(dev.duration / 60)}m ${dev.duration % 60}s</div>
                        <div>📦 ${dev.packets} bytes</div>
                        <div style="color: ${signalColor};">📶 ${signalText}</div>
                    </div>

                    ${dev.channel || dev.encryption !== 'Unknown' ? `
                    <div class="device-meta" style="grid-template-columns: repeat(3, 1fr);">
                        ${dev.channel ? `<div>📡 Ch ${dev.channel}</div>` : '<div></div>'}
                        ${dev.encryption !== 'Unknown' && dev.encryption !== 'None' ? `<div>🔒 ${dev.encryption}</div>` : dev.encryption === 'None' ? '<div>🔓 Open</div>' : '<div></div>'}
                        ${dev.frequency > 0 ? `<div>📻 ${(dev.frequency / 1000).toFixed(0)} MHz</div>` : '<div></div>'}
                    </div>` : ''}

                    <div class="device-meta">
                        <div>🕐 First: ${dev.first_seen}</div>
                        <div>🕐 Last: ${dev.last_seen}</div>
                        <div>⏰ ${dev.age_minutes}m ago</div>
                    </div>`;

            if (dev.ssids && dev.ssids.length > 0) {
                html += '<div class="device-ssids">📶 Probing SSIDs: ';
                html += dev.ssids.map(s => `<span class="ssid-tag">${s}</span>`).join('');
                html += '</div>';

                // WiGLE lookup button
                html += `<div style="margin-top: 8px;"><button class="btn btn-primary" style="width: 100%; padding: 8px; font-size: 11px;" onclick="lookupSSID('${dev.ssids[0]}', '${dev.mac}')">🌍 Lookup on WiGLE</button></div>`;
            }

            html += '</div>';
            return html;
        }

        function lookupSSID(ssid, mac) {
            const deviceEl = event.target.closest('.device-item');
            event.target.textContent = '⏳ Looking up...';
            event.target.disabled = true;

            fetch(`/api/wigle/lookup?ssid=${encodeURIComponent(ssid)}`)
                .then(r => r.json())
                .then(data => {
                    if (data.location) {
                        const loc = data.location;
                        const locHtml = `
                            <div class="wigle-location">
                                📍 ${loc.city}, ${loc.country}<br>
                                🌐 ${loc.lat.toFixed(6)}°, ${loc.lon.toFixed(6)}°<br>
                                🕐 Last seen: ${loc.lastupdt}
                            </div>`;
                        deviceEl.insertAdjacentHTML('beforeend', locHtml);
                        event.target.textContent = '✓ Located';
                    } else {
                        event.target.textContent = '✗ Not found';
                    }
                })
                .catch(err => {
                    event.target.textContent = '✗ Error';
                });
        }

        function startWardriving() {
            fetch('/api/start', {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    setTimeout(updateStatus, 3000);
                });
        }

        function stopWardriving() {
            fetch('/api/stop', {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    setTimeout(updateStatus, 2000);
                });
        }

        function scanNow() {
            updateStatus();
        }

        function refreshAll() {
            updateStatus();
            if (currentTab === 'blacklist') {
                updateBlacklist();
            }
        }

        function autoBlacklist() {
            if (!confirm('Add all currently visible devices to blacklist?')) return;

            fetch('/api/blacklist/auto', {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    alert(`✓ Added ${data.new} new devices to blacklist\nTotal: ${data.total} devices`);
                    updateBlacklist();
                    updateStatus();
                });
        }

        function clearBlacklist() {
            if (!confirm('Clear entire blacklist? This cannot be undone!')) return;

            fetch('/api/blacklist/clear', {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    alert('✓ Blacklist cleared');
                    updateBlacklist();
                    updateStatus();
                });
        }

        function removeFromBlacklist(mac) {
            if (!confirm(`Remove ${mac} from blacklist?`)) return;

            fetch('/api/blacklist/remove', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({mac: mac})
            })
                .then(r => r.json())
                .then(data => {
                    updateBlacklist();
                    updateStatus();
                });
        }

        function addToBlacklistSingle(mac, event) {
            event.stopPropagation();

            fetch('/api/blacklist/add', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({macs: [mac]})
            })
                .then(r => r.json())
                .then(data => {
                    updateStatus();
                });
        }

        // Auto-update every 5 seconds
        setInterval(updateStatus, 5000);
        setInterval(() => {
            if (currentTab === 'blacklist') updateBlacklist();
        }, 10000);

        // Initial load
        updateStatus();
        updateBlacklist();
    </script>
</body>
</html>
'''

def run_cmd(cmd, shell=False, timeout=5):
    """Execute command safely"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True,
                              text=True, timeout=timeout)
        return result.stdout.strip()
    except Exception:
        return ""

@app.route('/')
def index():
    return render_template_string(ENHANCED_HTML)

@app.route('/api/status')
def get_status():
    """Get basic system status"""
    status = {
        'system': {},
        'gps': {'fix': False, 'lat': 0, 'lon': 0, 'alt': 0, 'satellites': 0},
        'stats': {'networks': 0, 'devices': 0, 'packets': 0}
    }

    # System status
    status['system']['GPS'] = 'Running' if run_cmd(['systemctl', 'is-active', 'gpsd']) == 'active' else 'Stopped'
    status['system']['Kismet'] = 'Running' if run_cmd(['pgrep', '-x', 'kismet']) else 'Stopped'

    wlan1_info = run_cmd("iw dev wlan1 info 2>/dev/null", shell=True)
    if 'type monitor' in wlan1_info:
        status['system']['WiFi'] = 'Monitor Mode'
    elif wlan1_info:
        status['system']['WiFi'] = 'Managed Mode'
    else:
        status['system']['WiFi'] = 'Not Found'

    # GPS
    try:
        gps_raw = run_cmd("timeout 2 gpspipe -w -n 5 2>/dev/null | grep TPV | tail -1", shell=True)
        if gps_raw:
            gps_data = json.loads(gps_raw)
            if gps_data.get('mode', 0) >= 2:
                status['gps']['fix'] = True
                status['gps']['lat'] = gps_data.get('lat', 0)
                status['gps']['lon'] = gps_data.get('lon', 0)
                status['gps']['alt'] = gps_data.get('altHAE', 0)

        sky_raw = run_cmd("timeout 2 gpspipe -w -n 10 2>/dev/null | grep SKY | tail -1", shell=True)
        if sky_raw:
            sky_data = json.loads(sky_raw)
            status['gps']['satellites'] = len(sky_data.get('satellites', []))
    except:
        pass

    # Stats from Kismet
    if status['system']['Kismet'] == 'Running':
        latest_db = run_cmd("ls -t ~/Kismet-*.kismet 2>/dev/null | head -1", shell=True)
        if latest_db and os.path.exists(latest_db):
            try:
                devices = run_cmd(f"sqlite3 '{latest_db}' 'SELECT COUNT(*) FROM devices' 2>/dev/null", shell=True)
                status['stats']['devices'] = int(devices or 0)

                wifi = run_cmd(f"sqlite3 '{latest_db}' \"SELECT COUNT(*) FROM devices WHERE type LIKE '%Wi-Fi%'\" 2>/dev/null", shell=True)
                status['stats']['networks'] = int(wifi or 0)

                packets = run_cmd(f"sqlite3 '{latest_db}' 'SELECT COUNT(*) FROM packets' 2>/dev/null", shell=True)
                status['stats']['packets'] = int(packets or 0)
            except:
                pass

    return jsonify(status)

@app.route('/api/surveillance')
def get_surveillance():
    """Get surveillance detection analysis"""
    latest_db = run_cmd("ls -t ~/Kismet-*.kismet 2>/dev/null | head -1", shell=True)

    if not latest_db or not os.path.exists(latest_db):
        return jsonify({
            'total_devices': 0,
            'all_devices': [],
            'following': [],
            'persistent_count': 0,
            'error': 'No Kismet database found'
        })

    return jsonify(analyze_kismet_db(latest_db))

@app.route('/api/device/track/<mac>')
def get_device_track(mac):
    """Get GPS tracking data for a specific device"""
    latest_db = run_cmd("ls -t ~/Kismet-*.kismet 2>/dev/null | head -1", shell=True)

    if not latest_db or not os.path.exists(latest_db):
        return jsonify({'error': 'No database'})

    try:
        conn = sqlite3.connect(latest_db)
        cursor = conn.cursor()

        # Get device location history
        cursor.execute("""
            SELECT min_lat, min_lon, max_lat, max_lon, avg_lat, avg_lon, first_time, last_time
            FROM devices
            WHERE devmac = ?
        """, (mac,))

        row = cursor.fetchone()
        conn.close()

        if row and row[0] != 0:
            return jsonify({
                'mac': mac,
                'locations': [{
                    'lat': row[4] if row[4] != 0 else row[0],
                    'lon': row[5] if row[5] != 0 else row[1],
                    'first_seen': row[6],
                    'last_seen': row[7]
                }]
            })

        return jsonify({'mac': mac, 'locations': []})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/device/track/demo/<mac>')
def get_device_track_demo(mac):
    """Demo tracking data showing a device following you"""
    # Simulate a device moving along a path near 1521 N Waverly St
    demo_path = [
        {'lat': 37.1500, 'lon': -113.5300, 'time': '2025-12-13 23:00:00'},
        {'lat': 37.1505, 'lon': -113.5295, 'time': '2025-12-13 23:05:00'},
        {'lat': 37.1510, 'lon': -113.5292, 'time': '2025-12-13 23:10:00'},
        {'lat': 37.1515, 'lon': -113.5291, 'time': '2025-12-13 23:15:00'},
        {'lat': 37.1518, 'lon': -113.5292, 'time': '2025-12-13 23:20:00'},  # Near your house
        {'lat': 37.1522, 'lon': -113.5290, 'time': '2025-12-13 23:25:00'},
        {'lat': 37.1527, 'lon': -113.5285, 'time': '2025-12-13 23:30:00'},
    ]

    return jsonify({
        'mac': mac,
        'locations': demo_path,
        'is_demo': True
    })

@app.route('/api/wigle/lookup')
def wigle_lookup():
    """Lookup SSID on WiGLE"""
    ssid = request.args.get('ssid', '')
    if not ssid:
        return jsonify({'error': 'No SSID provided'})

    location = query_wigle_ssid(ssid)
    return jsonify({'location': location})

@app.route('/api/wigle/nearby')
def wigle_nearby():
    """Get nearby networks from WiGLE"""
    lat = request.args.get('lat', type=float)
    lon = request.args.get('lon', type=float)

    if not lat or not lon:
        return jsonify({'error': 'Location required'})

    try:
        # Search WiGLE for networks within ~1km
        response = requests.get(
            'https://api.wigle.net/api/v2/network/search',
            params={
                'latrange1': lat - 0.01,
                'latrange2': lat + 0.01,
                'longrange1': lon - 0.01,
                'longrange2': lon + 0.01,
                'resultsPerPage': 50
            },
            headers=get_wigle_auth(),
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            networks = []
            for result in data.get('results', [])[:50]:
                networks.append({
                    'ssid': result.get('ssid', 'Hidden'),
                    'mac': result.get('netid', ''),
                    'lat': result.get('trilat'),
                    'lon': result.get('trilong'),
                    'encryption': result.get('encryption', 'Unknown'),
                    'channel': result.get('channel', 0),
                    'lastupdt': result.get('lastupdt', ''),
                    'type': result.get('type', 'WiFi')
                })
            return jsonify({'networks': networks, 'count': len(networks)})
    except Exception as e:
        return jsonify({'error': str(e)})

    return jsonify({'networks': [], 'count': 0})

@app.route('/api/start', methods=['POST'])
def start_wardriving():
    """Start wardriving"""
    try:
        subprocess.run(['sudo', 'systemctl', 'restart', 'gpsd'], capture_output=True)
        time.sleep(1)

        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan1', 'down'], capture_output=True)
        subprocess.run(['sudo', 'iw', 'dev', 'wlan1', 'set', 'type', 'monitor'], capture_output=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan1', 'up'], capture_output=True)
        time.sleep(1)

        subprocess.Popen(['kismet', '-c', 'wlan1', '--daemonize', '--silent'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return jsonify({'status': 'success', 'message': '✓ Started'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'✗ Error: {str(e)}'})

@app.route('/api/stop', methods=['POST'])
def stop_wardriving():
    """Stop wardriving"""
    try:
        subprocess.run(['sudo', 'pkill', '-9', 'kismet'], capture_output=True)
        time.sleep(1)

        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan1', 'down'], capture_output=True)
        subprocess.run(['sudo', 'iw', 'dev', 'wlan1', 'set', 'type', 'managed'], capture_output=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan1', 'up'], capture_output=True)

        return jsonify({'status': 'success', 'message': '✓ Stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'✗ Error: {str(e)}'})

@app.route('/api/blacklist')
def get_blacklist_api():
    """Get blacklist"""
    return jsonify({'blacklist': sorted(list(get_blacklist()))})

@app.route('/api/whitelist')
def get_whitelist_api():
    """Get whitelist"""
    return jsonify({'whitelist': sorted(list(get_whitelist()))})

@app.route('/api/blacklist/add', methods=['POST'])
def add_to_blacklist():
    """Add MAC(s) to blacklist"""
    data = request.get_json()
    macs = data.get('macs', [])
    if isinstance(macs, str):
        macs = [macs]

    blacklist = get_blacklist()
    blacklist.update(macs)
    save_list(BLACKLIST_PATH, blacklist)

    return jsonify({'status': 'success', 'count': len(blacklist)})

@app.route('/api/blacklist/remove', methods=['POST'])
def remove_from_blacklist():
    """Remove MAC from blacklist"""
    data = request.get_json()
    mac = data.get('mac')

    blacklist = get_blacklist()
    blacklist.discard(mac)
    save_list(BLACKLIST_PATH, blacklist)

    return jsonify({'status': 'success', 'count': len(blacklist)})

@app.route('/api/blacklist/clear', methods=['POST'])
def clear_blacklist():
    """Clear entire blacklist"""
    save_list(BLACKLIST_PATH, set())
    return jsonify({'status': 'success'})

@app.route('/api/blacklist/auto', methods=['POST'])
def auto_blacklist():
    """Auto-blacklist all current devices"""
    latest_db = run_cmd("ls -t ~/Kismet-*.kismet 2>/dev/null | head -1", shell=True)

    if not latest_db or not os.path.exists(latest_db):
        return jsonify({'status': 'error', 'message': 'No database found'})

    try:
        conn = sqlite3.connect(latest_db)
        cursor = conn.cursor()
        cursor.execute('SELECT devmac FROM devices')
        current_macs = [row[0] for row in cursor.fetchall()]
        conn.close()

        blacklist = get_blacklist()
        old_count = len(blacklist)
        blacklist.update(current_macs)
        save_list(BLACKLIST_PATH, blacklist)

        return jsonify({
            'status': 'success',
            'added': len(current_macs),
            'total': len(blacklist),
            'new': len(blacklist) - old_count
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    print("=" * 70)
    print("🚨  SURVEILLANCE DETECTION DASHBOARD")
    print("=" * 70)
    print(f"📡 Access:    http://localhost:5000")
    print(f"🎯 Features:  Device tracking, WiGLE integration, Following detection")
    print(f"🛰️ GPS:       Real-time location tracking")
    print(f"🔍 Analysis:  Automatic surveillance pattern detection")
    print("=" * 70)
    print("")

    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
