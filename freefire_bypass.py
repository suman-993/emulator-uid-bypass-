import json
import logging
import random
import threading
import time
import os
import sys
import subprocess
import requests
from mitmproxy import http, options
from mitmproxy.tools import dump
import re
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import tempfile
import shutil
from pathlib import Path

# Configuration
WHITELIST_FILE = 'whitelist.json'
LOG_FILE = 'server.log'
PROXY_PORT = 5555
CERTIFICATE_URL = "http://mitm.it/cert/pem"
ADB_PATH = "adb"  # Will try to find ADB in PATH

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Load or initialize whitelist
def load_whitelist():
    try:
        with open(WHITELIST_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_whitelist(whitelist):
    with open(WHITELIST_FILE, 'w') as f:
        json.dump(whitelist, f, indent=4)

def is_uid_whitelisted(uid):
    whitelist = load_whitelist()
    return uid in whitelist

def add_uid_to_whitelist(uid):
    whitelist = load_whitelist()
    if uid not in whitelist:
        whitelist.append(uid)
        save_whitelist(whitelist)
        logging.info(f"Added UID {uid} to whitelist")
    else:
        logging.info(f"UID {uid} is already in whitelist")

# MSI App Player specific detection patterns
MSI_PATTERNS = [
    "msi", "msi app player", "4.240.15.6305", "bluestacks", "bst", "bstwebruntime",
    "android sdk built for x86", "emulator", "vbox", "virtualbox", "qemu", "goldfish"
]

# Device profiles optimized for MSI App Player
MOBILE_PROFILES = {
    "samsung_galaxy_s20": {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-G981B Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/87.0.4280.141 Mobile Safari/537.36",
        "X-Requested-With": "com.dts.freefireth",
        "Device-ID": "android-28c7d93a4b6e1f5g",
        "Device-Info": "Android 11; SM-G981B; samsung; samsung; en_US",
        "Screen-Resolution": "1080x2400",
        "Device-Model": "SM-G981B",
        "Device-Brand": "samsung",
        "Device-Manufacturer": "samsung",
        "Device-OS": "Android",
        "Device-OS-Version": "11",
        "Device-Hardware": "exynos990",
        "Network-Type": "WIFI",
        "Carrier": "Android",
        "Country": "US",
        "Language": "en"
    },
    "xiaomi_redmi_note_10": {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; Redmi Note 10 Pro Build/RKQ1.200826.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.105 Mobile Safari/537.36",
        "X-Requested-With": "com.dts.freefireth",
        "Device-ID": "android-39d8e74b5c2f1a6h",
        "Device-Info": "Android 11; Redmi Note 10 Pro; xiaomi; Redmi; en_US",
        "Screen-Resolution": "1080x2400",
        "Device-Model": "Redmi Note 10 Pro",
        "Device-Brand": "xiaomi",
        "Device-Manufacturer": "xiaomi",
        "Device-OS": "Android",
        "Device-OS-Version": "11",
        "Device-Hardware": "sm7125",
        "Network-Type": "WIFI",
        "Carrier": "Android",
        "Country": "US",
        "Language": "en"
    },
    "oneplus_8t": {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; KB2003 Build/RP1A.201005.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/87.0.4280.141 Mobile Safari/537.36",
        "X-Requested-With": "com.dts.freefireth",
        "Device-ID": "android-47f9a83b6d2e1c7i",
        "Device-Info": "Android 11; KB2003; OnePlus; OnePlus8T; en_US",
        "Screen-Resolution": "1080x2400",
        "Device-Model": "KB2003",
        "Device-Brand": "OnePlus",
        "Device-Manufacturer": "OnePlus",
        "Device-OS": "Android",
        "Device-OS-Version": "11",
        "Device-Hardware": "sm8250",
        "Network-Type": "WIFI",
        "Carrier": "Android",
        "Country": "US",
        "Language": "en"
    }
}

# Known Free Fire server domains
FREE_FIRE_DOMAINS = [
    "freefiremobile.com", "garena.com", "garenanow.com", "dtsfreefire.com",
    "gameapi.freefiremobile.com", "api.freefiremobile.com", "patch.freefiremobile.com",
    "ffinfo.freefiremobile.com", "login.freefiremobile.com", "settings.freefiremobile.com"
]

# Mitmproxy addon to modify requests and responses
class FreeFireProxy:
    def __init__(self, profile_name="samsung_galaxy_s20"):
        self.whitelisted_uid = "default_whitelisted_uid"
        self.current_profile = profile_name
        logging.info(f"Free Fire Proxy initialized with profile: {self.current_profile}")
        logging.info(f"MSI App Player 4.240.15.6305 detected - applying specialized transformations")

    def is_freefire_request(self, flow):
        """Check if this is a Free Fire related request"""
        host = flow.request.host.lower()
        return any(domain in host for domain in FREE_FIRE_DOMAINS)

    def is_msi_emulator_detected(self, flow):
        """Check if the request contains MSI emulator indicators"""
        # Check headers
        for header, value in flow.request.headers.items():
            if any(pattern in value.lower() for pattern in MSI_PATTERNS):
                return True
        
        # Check body for emulator indicators
        if flow.request.content:
            try:
                content = flow.request.content.decode('utf-8', errors='ignore').lower()
                if any(pattern in content for pattern in MSI_PATTERNS):
                    return True
            except:
                pass
                
        return False

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            if self.is_freefire_request(flow):
                profile = MOBILE_PROFILES[self.current_profile]
                
                # Log original request details
                original_ua = flow.request.headers.get("User-Agent", "")
                logging.info(f"Processing Free Fire request to: {flow.request.host}")
                
                # Check for MSI emulator detection
                if self.is_msi_emulator_detected(flow):
                    logging.warning("MSI emulator detection patterns found! Applying specialized phone transformation.")
                
                # Apply mobile phone profile to headers
                for header, value in profile.items():
                    flow.request.headers[header] = value
                
                # Handle UID modification
                uid = flow.request.headers.get("X-UID") or flow.request.headers.get("x-uid") or flow.request.headers.get("UID")
                if uid:
                    if is_uid_whitelisted(uid):
                        logging.info(f"Whitelisted UID {uid} allowed to connect.")
                    else:
                        flow.request.headers["X-UID"] = self.whitelisted_uid
                        logging.info(f"Modified UID from {uid} to {self.whitelisted_uid}")
                else:
                    # Add UID if missing
                    flow.request.headers["X-UID"] = self.whitelisted_uid
                    logging.info(f"Added UID: {self.whitelisted_uid}")
                
                # Special handling for MSI-specific headers
                if "Bluestacks" in original_ua or "MSI" in original_ua:
                    flow.request.headers["X-Bluestacks-Sku"] = "MSI"
                    flow.request.headers["X-Original-User-Agent"] = original_ua
                
                # Modify request body if it contains device info
                if flow.request.content:
                    try:
                        content = flow.request.content.decode('utf-8')
                        
                        # Replace MSI emulator indicators in body
                        for pattern in MSI_PATTERNS:
                            if pattern in content.lower():
                                replacement = self.current_profile.split('_')[1]
                                content = re.sub(
                                    pattern, 
                                    replacement, 
                                    content, 
                                    flags=re.IGNORECASE
                                )
                        
                        # Update device info in JSON body if present
                        if any(keyword in content.lower() for keyword in ['device', 'model', 'hardware', 'emulator']):
                            try:
                                data = json.loads(content)
                                if 'device' in data:
                                    if 'model' in data['device']:
                                        data['device']['model'] = profile['Device-Model']
                                    if 'brand' in data['device']:
                                        data['device']['brand'] = profile['Device-Brand']
                                    if 'manufacturer' in data['device']:
                                        data['device']['manufacturer'] = profile['Device-Manufacturer']
                                    if 'hardware' in data['device']:
                                        data['device']['hardware'] = profile['Device-Hardware']
                                content = json.dumps(data)
                            except:
                                # If not JSON, try to modify as text
                                content = content.replace('MSI', profile['Device-Brand'])
                                content = content.replace('msi', profile['Device-Brand'].lower())
                                content = content.replace('Bluestacks', profile['Device-Brand'])
                                content = content.replace('bluestacks', profile['Device-Brand'].lower())
                        
                        flow.request.content = content.encode('utf-8')
                    except Exception as e:
                        logging.error(f"Error modifying request content: {e}")
                
                logging.info(f"Transformed MSI request to appear as: {profile['Device-Model']}")
                
        except Exception as e:
            logging.error(f"Error modifying request: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            if self.is_freefire_request(flow):
                # Check if the response contains emulator detection or ban warnings
                content_type = flow.response.headers.get("Content-Type", "").lower()
                
                if flow.response.content:
                    try:
                        content = flow.response.content.decode('utf-8')
                        
                        # Check for ban or emulator detection responses
                        detection_keywords = ['emulator', 'ban', 'cheat', 'invalid', 'suspicious', 'msi', 'bluestacks']
                        if any(keyword in content.lower() for keyword in detection_keywords):
                            logging.warning(f"Potential detection in response from: {flow.request.host}")
                            
                            # Try to parse and modify JSON response
                            if "application/json" in content_type:
                                try:
                                    data = json.loads(content)
                                    if 'message' in data and any(keyword in str(data['message']).lower() for keyword in detection_keywords):
                                        data['message'] = "Success"
                                        data['status'] = 1
                                        flow.response.content = json.dumps(data).encode('utf-8')
                                        logging.info("Modified suspicious JSON response")
                                except:
                                    pass
                            else:
                                # If not JSON, try to modify text response
                                for keyword in detection_keywords:
                                    if keyword in content.lower():
                                        content = content.replace(keyword, 'device')
                                        content = content.replace(keyword.capitalize(), 'Device')
                                flow.response.content = content.encode('utf-8')
                                logging.info("Modified text response with detection keywords")
                    except:
                        pass
                        
        except Exception as e:
            logging.error(f"Error modifying response: {e}")

# ADB functions for automatic certificate installation
class ADBHelper:
    def __init__(self):
        self.adb_path = self.find_adb()
        
    def find_adb(self):
        """Try to find ADB executable"""
        # Check common locations
        possible_paths = [
            "adb",
            "platform-tools/adb",
            os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb"),
            os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe")
        ]
        
        for path in possible_paths:
            try:
                subprocess.run([path, "version"], capture_output=True, check=True)
                return path
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        return None
    
    def check_device_connected(self):
        """Check if an Android device is connected via ADB"""
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            
            # Check if any device is connected (excluding header line)
            if len(lines) > 1 and "device" in lines[1]:
                return True, "Device connected"
            else:
                return False, "No device connected"
        except subprocess.CalledProcessError as e:
            return False, f"ADB error: {e}"
    
    def install_certificate(self, cert_path):
        """Install certificate on Android device"""
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            # Push certificate to device
            subprocess.run([self.adb_path, "push", cert_path, "/sdcard/mitmproxy-ca-cert.cer"], 
                          capture_output=True, check=True)
            
            # Try to install the certificate
            result = subprocess.run([
                self.adb_path, "shell", 
                "su -c", 
                "mv /sdcard/mitmproxy-ca-cert.cer /system/etc/security/cacerts/ &&",
                "chmod 644 /system/etc/security/cacerts/mitmproxy-ca-cert.cer"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, "Certificate installed successfully"
            else:
                # Fallback to user certificate installation
                return self.install_user_certificate(cert_path)
                
        except subprocess.CalledProcessError as e:
            return False, f"Certificate installation failed: {e}"
    
    def install_user_certificate(self, cert_path):
        """Install certificate as user certificate (non-root)"""
        try:
            # For non-root devices, we need to use the settings command
            # This method may not work on all Android versions
            subprocess.run([self.adb_path, "push", cert_path, "/sdcard/mitmproxy-ca-cert.cer"], 
                          capture_output=True, check=True)
            
            # Try to install via security settings (may require user interaction)
            subprocess.run([self.adb_path, "shell", "am", "start", 
                          "-a", "android.intent.action.VIEW", 
                          "-t", "application/x-x509-ca-cert", 
                          "-d", "file:///sdcard/mitmproxy-ca-cert.cer"], 
                         capture_output=True)
            
            return True, "Certificate pushed to device. Please complete installation manually in the emulator."
            
        except subprocess.CalledProcessError as e:
            return False, f"User certificate installation failed: {e}"
    
    def set_proxy(self, host, port):
        """Set proxy settings on Android device"""
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            # Set global HTTP proxy
            subprocess.run([
                self.adb_path, "shell", 
                "settings put global http_proxy", f"{host}:{port}"
            ], capture_output=True, check=True)
            
            return True, f"Proxy set to {host}:{port}"
        except subprocess.CalledProcessError as e:
            return False, f"Proxy setting failed: {e}"
    
    def clear_proxy(self):
        """Clear proxy settings"""
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            subprocess.run([
                self.adb_path, "shell",
                "settings put global http_proxy :0"
            ], capture_output=True, check=True)
            return True, "Proxy cleared"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to clear proxy: {e}"

# GUI Application
class FreeFireProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Free Fire MSI App Player Protection")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Proxy variables
        self.proxy_thread = None
        self.proxy = None
        self.is_running = False
        
        # ADB helper
        self.adb_helper = ADBHelper()
        
        # Create GUI
        self.create_widgets()
        
        # Load whitelist
        self.load_whitelist()
        
        # Set default profile
        self.current_profile = "samsung_galaxy_s20"
        
        # Check ADB status
        self.check_adb_status()
        
    def create_widgets(self):
        # Create tabs
        tab_control = ttk.Notebook(self.root)
        
        # Main tab
        self.main_tab = ttk.Frame(tab_control)
        tab_control.add(self.main_tab, text='Main Control')
        
        # Settings tab
        self.settings_tab = ttk.Frame(tab_control)
        tab_control.add(self.settings_tab, text='Settings')
        
        # Logs tab
        self.logs_tab = ttk.Frame(tab_control)
        tab_control.add(self.logs_tab, text='Logs')
        
        tab_control.pack(expand=1, fill='both')
        
        # Main tab content
        self.create_main_tab()
        
        # Settings tab content
        self.create_settings_tab()
        
        # Logs tab content
        self.create_logs_tab()
        
    def create_main_tab(self):
        # Status frame
        status_frame = ttk.LabelFrame(self.main_tab, text="Status", padding=10)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.adb_status = ttk.Label(status_frame, text="ADB: Checking...")
        self.adb_status.pack(anchor='w')
        
        self.proxy_status = ttk.Label(status_frame, text="Proxy: Stopped")
        self.proxy_status.pack(anchor='w')
        
        self.cert_status = ttk.Label(status_frame, text="Certificate: Not installed")
        self.cert_status.pack(anchor='w')
        
        # Control frame
        control_frame = ttk.LabelFrame(self.main_tab, text="Control", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        # Profile selection
        ttk.Label(control_frame, text="Device Profile:").grid(row=0, column=0, sticky='w', pady=5)
        self.profile_var = tk.StringVar(value=self.current_profile)
        profile_combo = ttk.Combobox(control_frame, textvariable=self.profile_var, 
                                    values=list(MOBILE_PROFILES.keys()), state='readonly')
        profile_combo.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        profile_combo.bind('<<ComboboxSelected>>', self.on_profile_change)
        
        # Proxy controls
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Proxy", command=self.start_proxy)
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Proxy", command=self.stop_proxy, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        # Setup frame
        setup_frame = ttk.LabelFrame(self.main_tab, text="Setup", padding=10)
        setup_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(setup_frame, text="Install Certificate", 
                  command=self.install_certificate).pack(side='left', padx=5)
        
        ttk.Button(setup_frame, text="Set Proxy", 
                  command=self.set_proxy).pack(side='left', padx=5)
        
        ttk.Button(setup_frame, text="Clear Proxy", 
                  command=self.clear_proxy).pack(side='left', padx=5)
        
        ttk.Button(setup_frame, text="Full Auto Setup", 
                  command=self.full_auto_setup).pack(side='left', padx=5)
        
    def create_settings_tab(self):
        # Whitelist management
        whitelist_frame = ttk.LabelFrame(self.settings_tab, text="UID Whitelist", padding=10)
        whitelist_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Whitelist listbox
        self.whitelist_listbox = tk.Listbox(whitelist_frame, height=10)
        self.whitelist_listbox.pack(fill='both', expand=True, pady=5)
        
        # Whitelist controls
        control_frame = ttk.Frame(whitelist_frame)
        control_frame.pack(fill='x', pady=5)
        
        self.uid_entry = ttk.Entry(control_frame)
        self.uid_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        ttk.Button(control_frame, text="Add UID", 
                  command=self.add_uid).pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Remove Selected", 
                  command=self.remove_uid).pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Clear All", 
                  command=self.clear_whitelist).pack(side='left', padx=5)
        
        # Advanced settings
        advanced_frame = ttk.LabelFrame(self.settings_tab, text="Advanced", padding=10)
        advanced_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(advanced_frame, text="Proxy Port:").grid(row=0, column=0, sticky='w', pady=5)
        self.port_var = tk.StringVar(value=str(PROXY_PORT))
        ttk.Entry(advanced_frame, textvariable=self.port_var, width=10).grid(row=0, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Button(advanced_frame, text="Browse ADB Path", 
                  command=self.browse_adb_path).grid(row=1, column=0, columnspan=2, pady=5)
        
    def create_logs_tab(self):
        # Log text area
        log_frame = ttk.LabelFrame(self.logs_tab, text="Live Logs", padding=10)
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, state='disabled')
        self.log_text.pack(fill='both', expand=True)
        
        # Log controls
        control_frame = ttk.Frame(log_frame)
        control_frame.pack(fill='x', pady=5)
        
        ttk.Button(control_frame, text="Clear Logs", 
                  command=self.clear_logs).pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Save Logs", 
                  command=self.save_logs).pack(side='left', padx=5)
        
    def on_profile_change(self, event):
        self.current_profile = self.profile_var.get()
        logging.info(f"Profile changed to: {self.current_profile}")
        
    def check_adb_status(self):
        connected, message = self.adb_helper.check_device_connected()
        status_text = f"ADB: {message}"
        self.adb_status.config(text=status_text)
        return connected
        
    def install_certificate(self):
        if not self.check_adb_status():
            messagebox.showerror("Error", "No device connected via ADB")
            return
            
        try:
            # Download certificate
            response = requests.get(CERTIFICATE_URL)
            if response.status_code == 200:
                # Save to temporary file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.cer') as f:
                    f.write(response.content)
                    cert_path = f.name
                
                # Install certificate
                success, message = self.adb_helper.install_certificate(cert_path)
                
                # Clean up
                os.unlink(cert_path)
                
                if success:
                    self.cert_status.config(text="Certificate: Installed")
                    messagebox.showinfo("Success", message)
                else:
                    messagebox.showerror("Error", message)
            else:
                messagebox.showerror("Error", "Failed to download certificate")
        except Exception as e:
            messagebox.showerror("Error", f"Certificate installation failed: {str(e)}")
            
    def set_proxy(self):
        if not self.check_adb_status():
            messagebox.showerror("Error", "No device connected via ADB")
            return
            
        try:
            port = int(self.port_var.get())
            success, message = self.adb_helper.set_proxy("127.0.0.1", port)
            if success:
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            messagebox.showerror("Error", f"Proxy setup failed: {str(e)}")
            
    def clear_proxy(self):
        if not self.check_adb_status():
            messagebox.showerror("Error", "No device connected via ADB")
            return
            
        try:
            success, message = self.adb_helper.clear_proxy()
            if success:
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear proxy: {str(e)}")
            
    def full_auto_setup(self):
        if not self.check_adb_status():
            messagebox.showerror("Error", "No device connected via ADB")
            return
            
        # Install certificate
        self.install_certificate()
        
        # Set proxy
        self.set_proxy()
        
        # Start proxy
        self.start_proxy()
        
        messagebox.showinfo("Setup Complete", "Full auto setup completed successfully!")
        
    def start_proxy(self):
        if self.is_running:
            return
            
        try:
            port = int(self.port_var.get())
            
            # Create proxy instance
            self.proxy = FreeFireProxy(self.current_profile)
            
            # Configure mitmproxy options
            opts = options.Options(
                listen_port=port,
                ssl_insecure=True,
                upstream_cert=False,
                mode=['regular']
            )
            
            # Start proxy in separate thread
            self.is_running = True
            self.proxy_thread = threading.Thread(target=self.run_proxy, args=(opts,))
            self.proxy_thread.daemon = True
            self.proxy_thread.start()
            
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            self.proxy_status.config(text=f"Proxy: Running on port {port}")
            
            logging.info(f"Proxy server started on port {port}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start proxy: {str(e)}")
            self.is_running = False
            
    def stop_proxy(self):
        if not self.is_running:
            return
            
        self.is_running = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.proxy_status.config(text="Proxy: Stopped")
        
        logging.info("Proxy server stopped")
        
    def run_proxy(self, opts):
        try:
            master = dump.DumpMaster(opts)
            master.addons.add(self.proxy)
            
            while self.is_running:
                master.run()
                time.sleep(0.1)
                
        except Exception as e:
            logging.error(f"Proxy error: {e}")
            self.is_running = False
            
    def load_whitelist(self):
        whitelist = load_whitelist()
        self.whitelist_listbox.delete(0, tk.END)
        for uid in whitelist:
            self.whitelist_listbox.insert(tk.END, uid)
            
    def add_uid(self):
        uid = self.uid_entry.get().strip()
        if uid:
            add_uid_to_whitelist(uid)
            self.load_whitelist()
            self.uid_entry.delete(0, tk.END)
            logging.info(f"Added UID to whitelist: {uid}")
        else:
            messagebox.showwarning("Warning", "Please enter a UID")
            
    def remove_uid(self):
        selection = self.whitelist_listbox.curselection()
        if selection:
            uid = self.whitelist_listbox.get(selection[0])
            whitelist = load_whitelist()
            if uid in whitelist:
                whitelist.remove(uid)
                save_whitelist(whitelist)
                self.load_whitelist()
                logging.info(f"Removed UID from whitelist: {uid}")
        else:
            messagebox.showwarning("Warning", "Please select a UID to remove")
            
    def clear_whitelist(self):
        if messagebox.askyesno("Confirm", "Clear all UIDs from whitelist?"):
            save_whitelist([])
            self.load_whitelist()
            logging.info("Cleared all UIDs from whitelist")
            
    def browse_adb_path(self):
        path = filedialog.askopenfilename(
            title="Select ADB executable",
            filetypes=[("ADB executable", "adb*"), ("All files", "*.*")]
        )
        if path:
            self.adb_helper.adb_path = path
            self.check_adb_status()
            
    def clear_logs(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
        
    def save_logs(self):
        path = filedialog.asksaveasfilename(
            title="Save logs",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            try:
                with open(path, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Logs saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
                
    def log_message(self, message):
        """Add message to log text area"""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

# Custom log handler for GUI
class GUIHandler(logging.Handler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
        
    def emit(self, record):
        log_entry = self.format(record)
        self.gui.log_message(log_entry)

# Main application
def main():
    root = tk.Tk()
    app = FreeFireProxyGUI(root)
    
    # Add GUI log handler
    gui_handler = GUIHandler(app)
    gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(gui_handler)
    
    # Handle application close
    def on_closing():
        if app.is_running:
            app.stop_proxy()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()