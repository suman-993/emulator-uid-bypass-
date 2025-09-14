import json
import logging
import threading
import time
import os
import subprocess
import requests
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
import re
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import tempfile
import asyncio

# Configuration
WHITELIST_FILE = 'whitelist.json'
LOG_FILE = 'server.log'
PROXY_PORT = 5555
CERTIFICATE_URL = "http://mitm.it/cert/pem"
ADB_PATH = "adb"

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

    def is_freefire_request(self, flow):
        host = flow.request.host.lower()
        return any(domain in host for domain in FREE_FIRE_DOMAINS)

    def is_msi_emulator_detected(self, flow):
        for header, value in flow.request.headers.items():
            if any(pattern in value.lower() for pattern in MSI_PATTERNS):
                return True
        
        if flow.request.content:
            try:
                content = flow.request.content.decode('utf-8', errors='ignore').lower()
                if any(pattern in content for pattern in MSI_PATTERNS):
                    return True
            except:
                pass
                
        return False

    def request(self, flow):
        try:
            if self.is_freefire_request(flow):
                profile = MOBILE_PROFILES[self.current_profile]
                original_ua = flow.request.headers.get("User-Agent", "")
                logging.info(f"Processing Free Fire request to: {flow.request.host}")
                
                if self.is_msi_emulator_detected(flow):
                    logging.warning("MSI emulator detection patterns found! Applying specialized phone transformation.")
                
                for header, value in profile.items():
                    if header not in ["Screen-Resolution", "Network-Type", "Carrier", "Country", "Language"]:
                        flow.request.headers[header] = value
                
                uid = flow.request.headers.get("X-UID") or flow.request.headers.get("x-uid") or flow.request.headers.get("UID")
                if uid:
                    if is_uid_whitelisted(uid):
                        logging.info(f"Whitelisted UID {uid} allowed to connect.")
                    else:
                        flow.request.headers["X-UID"] = self.whitelisted_uid
                        logging.info(f"Modified UID from {uid} to {self.whitelisted_uid}")
                else:
                    flow.request.headers["X-UID"] = self.whitelisted_uid
                    logging.info(f"Added UID: {self.whitelisted_uid}")
                
                if "Bluestacks" in original_ua or "MSI" in original_ua:
                    flow.request.headers["X-Bluestacks-Sku"] = "MSI"
                    flow.request.headers["X-Original-User-Agent"] = original_ua
                
                if flow.request.content:
                    try:
                        content = flow.request.content.decode('utf-8')
                        
                        for pattern in MSI_PATTERNS:
                            if pattern in content.lower():
                                replacement = self.current_profile.split('_')[1]
                                content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
                        
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

    def response(self, flow):
        try:
            if self.is_freefire_request(flow):
                content_type = flow.response.headers.get("Content-Type", "").lower()
                
                if flow.response.content:
                    try:
                        content = flow.response.content.decode('utf-8')
                        
                        detection_keywords = ['emulator', 'ban', 'cheat', 'invalid', 'suspicious', 'msi', 'bluestacks']
                        if any(keyword in content.lower() for keyword in detection_keywords):
                            logging.warning(f"Potential detection in response from: {flow.request.host}")
                            
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
        possible_paths = [
            "adb",
            "platform-tools/adb",
            os.path.join(os.environ.get("ANDROID_HOME", ""), "platform-tools", "adb"),
            os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Android", "Sdk", "platform-tools", "adb.exe")
        ]
        
        for path in possible_paths:
            try:
                subprocess.run([path, "version"], capture_output=True, check=True, timeout=10)
                return path
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        return None
    
    def check_device_connected(self):
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            result = subprocess.run([self.adb_path, "devices"], capture_output=True, text=True, check=True, timeout=10)
            lines = result.stdout.strip().split('\n')
            
            if len(lines) > 1 and any("device" in line and "offline" not in line for line in lines[1:]):
                return True, "Device connected"
            else:
                return False, "No device connected"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            return False, f"ADB error: {e}"
    
    def download_certificate(self):
        try:
            response = requests.get(CERTIFICATE_URL, timeout=10)
            if response.status_code == 200:
                # Create a temporary file
                cert_file = tempfile.NamedTemporaryFile(delete=False, suffix='.cer')
                cert_file.write(response.content)
                cert_file.close()
                return True, cert_file.name
            else:
                return False, f"Failed to download certificate: HTTP {response.status_code}"
        except Exception as e:
            return False, f"Certificate download failed: {e}"
    
    def install_certificate(self):
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            # Download the certificate
            success, cert_path = self.download_certificate()
            if not success:
                return False, cert_path
            
            # Push certificate to device
            push_result = subprocess.run(
                [self.adb_path, "push", cert_path, "/sdcard/mitmproxy-ca-cert.cer"], 
                capture_output=True, text=True, timeout=30
            )
            
            if push_result.returncode != 0:
                return False, f"Failed to push certificate: {push_result.stderr}"
            
            # For non-root devices, open the certificate installation dialog
            install_result = subprocess.run([
                self.adb_path, "shell", "am", "start",
                "-a", "android.intent.action.VIEW",
                "-t", "application/x-x509-ca-cert",
                "-d", "file:///sdcard/mitmproxy-ca-cert.cer"
            ], capture_output=True, text=True, timeout=30)
            
            # Clean up temporary file
            try:
                os.unlink(cert_path)
            except:
                pass
            
            if install_result.returncode == 0:
                return True, "Certificate pushed to device. Please complete installation manually in the emulator by following the prompts."
            else:
                return False, f"Failed to open certificate installation dialog: {install_result.stderr}"
                
        except subprocess.TimeoutExpired:
            return False, "Certificate installation timed out"
        except Exception as e:
            return False, f"Certificate installation failed: {e}"
    
    def set_proxy(self, host, port):
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            result = subprocess.run([
                self.adb_path, "shell", 
                "settings", "put", "global", "http_proxy", f"{host}:{port}"
            ], capture_output=True, text=True, timeout=30, check=True)
            
            return True, f"Proxy set to {host}:{port}"
        except subprocess.CalledProcessError as e:
            return False, f"Proxy setting failed: {e.stderr if hasattr(e, 'stderr') else str(e)}"
        except subprocess.TimeoutExpired:
            return False, "Proxy setting timed out"
    
    def clear_proxy(self):
        if not self.adb_path:
            return False, "ADB not found"
        
        try:
            subprocess.run([
                self.adb_path, "shell",
                "settings", "put", "global", "http_proxy", ":0"
            ], capture_output=True, check=True, timeout=30)
            return True, "Proxy cleared"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to clear proxy: {e.stderr if hasattr(e, 'stderr') else str(e)}"
        except subprocess.TimeoutExpired:
            return False, "Proxy clearing timed out"

# GUI Application
class FreeFireProxyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Free Fire MSI App Player Protection")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        self.current_profile = "samsung_galaxy_s20"
        self.proxy_thread = None
        self.proxy_addon = None
        self.master = None
        self.is_running = False
        self.adb_helper = ADBHelper()
        
        self.create_widgets()
        self.load_whitelist()
        self.check_adb_status()
        
    def create_widgets(self):
        tab_control = ttk.Notebook(self.root)
        
        self.main_tab = ttk.Frame(tab_control)
        tab_control.add(self.main_tab, text='Main Control')
        
        self.settings_tab = ttk.Frame(tab_control)
        tab_control.add(self.settings_tab, text='Settings')
        
        self.logs_tab = ttk.Frame(tab_control)
        tab_control.add(self.logs_tab, text='Logs')
        
        tab_control.pack(expand=1, fill='both')
        
        self.create_main_tab()
        self.create_settings_tab()
        self.create_logs_tab()
        
    def create_main_tab(self):
        status_frame = ttk.LabelFrame(self.main_tab, text="Status", padding=10)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.adb_status = ttk.Label(status_frame, text="ADB: Checking...")
        self.adb_status.pack(anchor='w')
        
        self.proxy_status = ttk.Label(status_frame, text="Proxy: Stopped")
        self.proxy_status.pack(anchor='w')
        
        self.cert_status = ttk.Label(status_frame, text="Certificate: Not installed")
        self.cert_status.pack(anchor='w')
        
        control_frame = ttk.LabelFrame(self.main_tab, text="Control", padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(control_frame, text="Device Profile:").grid(row=0, column=0, sticky='w', pady=5)
        self.profile_var = tk.StringVar(value=self.current_profile)
        profile_combo = ttk.Combobox(control_frame, textvariable=self.profile_var, 
                                    values=list(MOBILE_PROFILES.keys()), state='readonly')
        profile_combo.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        profile_combo.bind('<<ComboboxSelected>>', self.on_profile_change)
        
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Proxy", command=self.start_proxy)
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Proxy", command=self.stop_proxy, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        setup_frame = ttk.LabelFrame(self.main_tab, text="Setup", padding=10)
        setup_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(setup_frame, text="Install Certificate", command=self.install_certificate).pack(side='left', padx=5)
        ttk.Button(setup_frame, text="Set Proxy", command=self.set_proxy).pack(side='left', padx=5)
        ttk.Button(setup_frame, text="Clear Proxy", command=self.clear_proxy).pack(side='left', padx=5)
        ttk.Button(setup_frame, text="Check ADB", command=self.check_adb_status).pack(side='left', padx=5)
        
    def create_settings_tab(self):
        settings_frame = ttk.LabelFrame(self.settings_tab, text="Whitelist Management", padding=10)
        settings_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        ttk.Label(settings_frame, text="UID to whitelist:").pack(anchor='w', pady=5)
        
        uid_frame = ttk.Frame(settings_frame)
        uid_frame.pack(fill='x', pady=5)
        
        self.uid_var = tk.StringVar()
        ttk.Entry(uid_frame, textvariable=self.uid_var).pack(side='left', fill='x', expand=True, padx=(0, 5))
        ttk.Button(uid_frame, text="Add UID", command=self.add_uid).pack(side='right')
        
        ttk.Label(settings_frame, text="Whitelisted UIDs:").pack(anchor='w', pady=(10, 5))
        
        self.whitelist_listbox = tk.Listbox(settings_frame, height=10)
        self.whitelist_listbox.pack(fill='both', expand=True, pady=5)
        
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill='x', pady=5)
        
        ttk.Button(button_frame, text="Remove Selected", command=self.remove_uid).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Refresh List", command=self.load_whitelist).pack(side='left')
        
    def create_logs_tab(self):
        logs_frame = ttk.Frame(self.logs_tab)
        logs_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(logs_frame, height=20)
        self.log_text.pack(fill='both', expand=True)
        self.log_text.config(state='disabled')
        
        button_frame = ttk.Frame(logs_frame)
        button_frame.pack(fill='x', pady=5)
        
        ttk.Button(button_frame, text="Clear Logs", command=self.clear_logs).pack(side='left')
        ttk.Button(button_frame, text="Save Logs", command=self.save_logs).pack(side='left', padx=(5, 0))
        
    def on_profile_change(self, event):
        self.current_profile = self.profile_var.get()
        if self.proxy_addon:
            self.proxy_addon.current_profile = self.current_profile
        logging.info(f"Profile changed to: {self.current_profile}")
        
    def check_adb_status(self):
        connected, message = self.adb_helper.check_device_connected()
        status_text = f"ADB: {'Connected' if connected else 'Not Connected'} - {message}"
        self.adb_status.config(text=status_text)
        return connected
        
    def install_certificate(self):
        success, message = self.adb_helper.install_certificate()
        if success:
            messagebox.showinfo("Success", message)
            self.cert_status.config(text="Certificate: Installation initiated")
        else:
            messagebox.showerror("Error", f"Certificate installation failed: {message}")
            
    def set_proxy(self):
        if not self.check_adb_status():
            messagebox.showerror("Error", "No device connected. Please connect your emulator first.")
            return
            
        success, message = self.adb_helper.set_proxy("127.0.0.1", PROXY_PORT)
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", f"Proxy setting failed: {message}")
            
    def clear_proxy(self):
        success, message = self.adb_helper.clear_proxy()
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", f"Proxy clearing failed: {message}")
            
    def add_uid(self):
        uid = self.uid_var.get().strip()
        if uid:
            add_uid_to_whitelist(uid)
            self.uid_var.set("")
            self.load_whitelist()
            messagebox.showinfo("Success", f"UID {uid} added to whitelist")
        else:
            messagebox.showwarning("Warning", "Please enter a valid UID")
            
    def remove_uid(self):
        selection = self.whitelist_listbox.curselection()
        if selection:
            uid = self.whitelist_listbox.get(selection[0])
            whitelist = load_whitelist()
            if uid in whitelist:
                whitelist.remove(uid)
                save_whitelist(whitelist)
                self.load_whitelist()
                messagebox.showinfo("Success", f"UID {uid} removed from whitelist")
        else:
            messagebox.showwarning("Warning", "Please select a UID to remove")
            
    def load_whitelist(self):
        self.whitelist_listbox.delete(0, tk.END)
        whitelist = load_whitelist()
        for uid in whitelist:
            self.whitelist_listbox.insert(tk.END, uid)
            
    def clear_logs(self):
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
        
    def save_logs(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Logs saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {e}")
                
    def start_proxy(self):
        if not self.check_adb_status():
            messagebox.showerror("Error", "No device connected. Please connect your emulator first.")
            return
            
        def run_proxy():
            try:
                opts = options.Options(listen_host='0.0.0.0', listen_port=PROXY_PORT)
                self.proxy_addon = FreeFireProxy(self.current_profile)
                self.master = DumpMaster(opts)
                self.master.addons.add(self.proxy_addon)
                
                self.is_running = True
                self.root.after(0, lambda: self.update_proxy_status("Proxy: Running"))
                
                logging.info(f"Starting proxy server on port {PROXY_PORT}")
                self.master.run()
                
            except Exception as e:
                logging.error(f"Proxy error: {e}")
                self.is_running = False
                self.root.after(0, lambda: self.update_proxy_status(f"Proxy: Error - {str(e)}"))
                
        self.proxy_thread = threading.Thread(target=run_proxy, daemon=True)
        self.proxy_thread.start()
        
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
    def stop_proxy(self):
        if self.master and self.is_running:
            self.master.shutdown()
            self.is_running = False
            self.update_proxy_status("Proxy: Stopped")
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            logging.info("Proxy server stopped")
            
    def update_proxy_status(self, status):
        self.proxy_status.config(text=status)
        
    def update_logs(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

# Custom log handler to update GUI
class GUIHandler(logging.Handler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
        
    def emit(self, record):
        log_entry = self.format(record)
        self.gui.root.after(0, lambda: self.gui.update_logs(log_entry))

def main():
    root = tk.Tk()
    app = FreeFireProxyGUI(root)
    
    # Add GUI log handler
    gui_handler = GUIHandler(app)
    gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger().addHandler(gui_handler)
    
    def on_closing():
        if app.is_running:
            app.stop_proxy()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()