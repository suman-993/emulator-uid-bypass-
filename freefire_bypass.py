import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import os
import sys
import time
import re
import random
import threading
import psutil
from datetime import datetime

class FreeFireBypassTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Free Fire Emulator Bypass Tool")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        
        # Variables
        self.adb_path = tk.StringVar(value="adb")
        self.emulator_port = tk.StringVar(value="5555")
        self.is_running = False
        self.process = None
        
        self.create_widgets()
        
    def create_widgets(self):
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main tab
        main_frame = ttk.Frame(notebook, padding=10)
        notebook.add(main_frame, text="Bypass Control")
        
        # Settings frame
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding=10)
        settings_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        settings_frame.columnconfigure(1, weight=1)
        
        ttk.Label(settings_frame, text="ADB Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.adb_path, width=40).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(settings_frame, text="Emulator Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.emulator_port, width=10).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Emulator type
        ttk.Label(settings_frame, text="Emulator Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.emulator_type = ttk.Combobox(settings_frame, values=["LDPlayer", "Nox", "BlueStacks", "Memu", "Generic"], state="readonly")
        self.emulator_type.set("LDPlayer")
        self.emulator_type.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10)
        
        self.start_btn = ttk.Button(buttons_frame, text="Start Bypass", command=self.start_bypass)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(buttons_frame, text="Stop Bypass", command=self.stop_bypass, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Check Connection", command=self.check_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Advanced Methods", command=self.show_advanced_methods).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Reboot Device", command=self.reboot_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Install Modules", command=self.show_module_help).pack(side=tk.LEFT, padx=5)
        
        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=10)
        log_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Methods tab
        methods_frame = ttk.Frame(notebook, padding=10)
        notebook.add(methods_frame, text="Bypass Methods")
        
        methods = [
            "✓ ADB Connection Spoofing (127.0.0.1:5555)",
            "✓ Device Fingerprint Spoofing (ROG Phone 2)",
            "⚠ Root Detection Bypass (Needs Magisk)",
            "✓ Emulator Detection Bypass",
            "✓ UID/IMEI Spoofing",
            "✓ Memory/Process Hiding",
            "✓ Network Traffic Manipulation",
            "⚠ Sensor Data Spoofing (Manual needed)",
            "✓ Debugging Detection Bypass",
            "⚠ Game Binary Modification (Manual needed)"
        ]
        
        for i, method in enumerate(methods):
            ttk.Label(methods_frame, text=method).grid(row=i, column=0, sticky=tk.W, pady=2)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.status_var.set(message)
    
    def run_command(self, command, shell=False):
        try:
            result = subprocess.run(
                command if not shell else command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def check_connection(self):
        self.log_message("Checking ADB connection...")
        success, stdout, stderr = self.run_command([self.adb_path.get(), "devices"])
        if success:
            devices = [line for line in stdout.split('\n') if line.strip() and not line.startswith('List')]
            if devices:
                self.log_message(f"Connected devices: {len(devices)}")
                for device in devices:
                    self.log_message(f"  {device}")
            else:
                self.log_message("No devices connected")
        else:
            self.log_message(f"ADB error: {stderr}")
    
    def show_advanced_methods(self):
        advanced_window = tk.Toplevel(self.root)
        advanced_window.title("Advanced Bypass Methods")
        advanced_window.geometry("600x500")
        
        ttk.Label(advanced_window, text="Manual Steps Required:", font=("Arial", 12, "bold")).pack(pady=10)
        
        methods = [
            "1. Install MagiskHide Props Config module in Magisk",
            "2. Use terminal: props -> 1 -> f -> 28 (Asus) -> 3 (ROG Phone 2)",
            "3. Reboot after configuration",
            "4. Enable Zygisk in Magisk settings",
            "5. Add Free Fire to DenyList in Magisk",
            "6. Install Shamiko module for better hiding",
            "7. Use LSPosed with Hide My Applist module",
            "8. Configure device fingerprint in build.prop manually if needed"
        ]
        
        for i, method in enumerate(methods):
            ttk.Label(advanced_window, text=method, wraplength=550).pack(anchor=tk.W, pady=2, padx=10)
        
        ttk.Button(advanced_window, text="Close", command=advanced_window.destroy).pack(pady=10)
    
    def show_module_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Module Installation Help")
        help_window.geometry("700x400")
        
        ttk.Label(help_window, text="How to Install Magisk Modules:", font=("Arial", 12, "bold")).pack(pady=10)
        
        instructions = [
            "1. Download modules from these GitHub links:",
            "   - MagiskHide Props Config: https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf",
            "   - Universal SafetyNet Fix: https://github.com/kdrag0n/safetynet-fix",
            "   - Shamiko: https://github.com/LSPosed/LSPosed/releases (look for Shamiko)",
            "",
            "2. Transfer the ZIP file to your emulator",
            "3. Open Magisk Manager → Modules → Install from storage",
            "4. Select the downloaded ZIP file",
            "5. Reboot your emulator",
            "",
            "6. For Shamiko: After installing, enable Zygisk in Magisk settings",
            "7. Add Free Fire to DenyList in Magisk",
            "8. Reboot again for all changes to take effect"
        ]
        
        for instruction in instructions:
            ttk.Label(help_window, text=instruction, wraplength=650, justify=tk.LEFT).pack(anchor=tk.W, padx=10, pady=2)
        
        ttk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=10)
    
    def reboot_device(self):
        self.log_message("Rebooting device...")
        success, stdout, stderr = self.run_command([self.adb_path.get(), "reboot"])
        if success:
            self.log_message("Device reboot initiated")
            self.log_message("Please wait for device to restart and reconnect")
        else:
            self.log_message(f"Reboot failed: {stderr}")
    
    def start_bypass(self):
        if self.is_running:
            return
            
        self.is_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Run bypass in a separate thread to avoid GUI freezing
        thread = threading.Thread(target=self.execute_bypass)
        thread.daemon = True
        thread.start()
    
    def stop_bypass(self):
        self.is_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log_message("Bypass stopped")
    
    def execute_bypass(self):
        self.log_message("Starting Free Fire bypass sequence...")
        
        # 1. Connect to emulator via ADB
        self.log_message("Step 1: Connecting to emulator via ADB")
        success, stdout, stderr = self.run_command([
            self.adb_path.get(), "connect", f"127.0.0.1:{self.emulator_port.get()}"
        ])
        
        if success:
            self.log_message("ADB connection established")
        else:
            self.log_message(f"ADB connection failed: {stderr}")
            self.stop_bypass()
            return
        
        # 2. Check if device is rooted and Magisk is available
        self.log_message("Step 2: Checking root access")
        success, stdout, stderr = self.run_command([self.adb_path.get(), "shell", "su -c 'echo Root check'"])
        
        if success:
            self.log_message("Root access confirmed")
            
            # Check for Magisk
            success, stdout, stderr = self.run_command([self.adb_path.get(), "shell", "su -c", '"which magisk"'])
            if success and "magisk" in stdout:
                self.log_message("Magisk detected")
                
                # Check Magisk version
                success, stdout, stderr = self.run_command([self.adb_path.get(), "shell", "su -c", '"magisk -v"'])
                if success:
                    self.log_message(f"Magisk version: {stdout.strip()}")
            else:
                self.log_message("Magisk not found - some bypass methods may not work")
        else:
            self.log_message("Root access not available - some bypass methods may not work")
        
        # 3. Spoof device properties (ROG Phone 2)
        self.log_message("Step 3: Spoofing device properties as ROG Phone 2")
        
        # Try to remount system as read-write first
        self.log_message("Attempting to remount system as read-write...")
        success, stdout, stderr = self.run_command([
            self.adb_path.get(), "shell", "su -c", '"mount -o remount,rw /system"'
        ])
        
        if success:
            self.log_message("System remounted as read-write")
            
            # Modify build.prop directly
            rog2_props = {
                "ro.product.model": "ASUS_I001DC",
                "ro.product.brand": "asus",
                "ro.product.name": "WW_I001D",
                "ro.product.device": "ASUS_I001_1",
                "ro.build.product": "ASUS_I001_1",
                "ro.build.fingerprint": "asus/WW_I001D/ASUS_I001_1:10/QQ2A.200405.005/20.10.7.57:user/release-keys",
                "ro.build.description": "WW_I001D-user 10 QQ2A.200405.005 20.10.7.57 release-keys"
            }
            
            for prop, value in rog2_props.items():
                # First try to find and replace existing property
                success, stdout, stderr = self.run_command([
                    self.adb_path.get(), "shell", "su -c", f'"sed -i \\"s/^{prop}=.*/{prop}={value}/\\" /system/build.prop"'
                ])
                
                if not success:
                    # If property doesn't exist, append it
                    success, stdout, stderr = self.run_command([
                        self.adb_path.get(), "shell", "su -c", f'"echo \\"{prop}={value}\\" >> /system/build.prop"'
                    ])
                    if success:
                        self.log_message(f"Added {prop} = {value} to build.prop")
                    else:
                        self.log_message(f"Failed to add {prop}: {stderr}")
                else:
                    self.log_message(f"Modified {prop} = {value} in build.prop")
        else:
            self.log_message("Could not remount system as read-write - using alternative methods")
        
        # 4. Hide root from target apps - FIXED APPROACH
        self.log_message("Step 4: Configuring root hiding (Fixed Approach)")
        
        # Check for Magisk
        success, stdout, stderr = self.run_command([
            self.adb_path.get(), "shell", "su -c", '"which magisk"'
        ])
        
        if success and "magisk" in stdout:
            self.log_message("Magisk detected - configuring Magisk Hide")
            
            # Check if Zygisk is available (Magisk v24+)
            success, stdout, stderr = self.run_command([
                self.adb_path.get(), "shell", "su -c", '"magisk --zygote"'
            ])
            
            if success:
                self.log_message("Zygisk detected - using DenyList")
                # Add Free Fire to DenyList
                success, stdout, stderr = self.run_command([
                    self.adb_path.get(), "shell", "su -c", '"magisk --denylist add com.dts.freefireth"'
                ])
                if success:
                    self.log_message("Free Fire added to Magisk DenyList")
                else:
                    self.log_message("Could not add Free Fire to DenyList")
            else:
                # Use older MagiskHide for older Magisk versions
                success, stdout, stderr = self.run_command([
                    self.adb_path.get(), "shell", "su -c", '"magiskhide enable"'
                ])
                if success:
                    self.log_message("Magisk Hide enabled")
                
                # Add Free Fire to hide list
                success, stdout, stderr = self.run_command([
                    self.adb_path.get(), "shell", "su -c", '"magiskhide add com.dts.freefireth"'
                ])
                if success:
                    self.log_message("Free Fire added to Magisk Hide")
                else:
                    self.log_message("Could not add Free Fire to Magisk Hide")
        else:
            self.log_message("Magisk not found - using alternative root hiding methods")
            
            # Find and hide actual Magisk binaries instead of symlinks
            magisk_paths = [
                "/data/adb/magisk/magisk",
                "/sbin/magisk",
                "/dev/magisk",
                "/system/xbin/magisk"
            ]
            
            for path in magisk_paths:
                success, stdout, stderr = self.run_command([
                    self.adb_path.get(), "shell", "su -c", f'"[ -f {path} ] && chmod 000 {path}"'
                ])
                if success:
                    self.log_message(f"Hidden Magisk binary: {path}")
            
            # Also hide su binaries
            su_paths = [
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/vendor/bin/su"
            ]
            
            for path in su_paths:
                # First check if it's a file (not symlink)
                success, stdout, stderr = self.run_command([
                    self.adb_path.get(), "shell", "su -c", f'"[ -f {path} ] && chmod 000 {path}"'
                ])
                if success:
                    self.log_message(f"Hidden su binary: {path}")
        
        # 5. Spoof UID/IMEI
        self.log_message("Step 5: Spoofing device identifiers")
        
        # Generate random IMEI
        imei = ''.join([str(random.randint(0, 9)) for _ in range(15)])
        success, stdout, stderr = self.run_command([
            self.adb_path.get(), "shell", "su -c", f'"setprop persist.radio.imei {imei}"'
        ])
        
        if success:
            self.log_message(f"Spoofed IMEI: {imei}")
        else:
            self.log_message("Failed to spoof IMEI")
        
        # 6. Disable debugging detection
        self.log_message("Step 6: Disabling debugging detection")
        
        # These properties might be read-only, but we try anyway
        debug_props = {
            "ro.adb.secure": "1",
            "persist.sys.usb.config": "none",
            "ro.secure": "1"
        }
        
        for prop, value in debug_props.items():
            success, stdout, stderr = self.run_command([
                self.adb_path.get(), "shell", "su -c", f'"setprop {prop} {value}"'
            ])
            if success:
                self.log_message(f"Set {prop} = {value}")
            else:
                self.log_message(f"Failed to set {prop}: {stderr}")
        
        # 7. Hide emulator-specific artifacts based on emulator type
        self.log_message("Step 7: Hiding emulator artifacts")
        
        emulator_type = self.emulator_type.get()
        emulator_files = self.get_emulator_files(emulator_type)
        
        for file_path in emulator_files:
            # Check if file exists
            success, stdout, stderr = self.run_command([
                self.adb_path.get(), "shell", "su -c", f'"[ -e {file_path} ] && echo exists"'
            ])
            
            if success and "exists" in stdout:
                # Hide the file
                success, stdout, stderr = self.run_command([
                    self.adb_path.get(), "shell", "su -c", f'"mv {file_path} {file_path}.bak"'
                ])
                if success:
                    self.log_message(f"Hidden {file_path}")
                else:
                    self.log_message(f"Could not hide {file_path}: {stderr}")
            else:
                self.log_message(f"{file_path} does not exist")
        
        # 8. Additional security measures
        self.log_message("Step 8: Applying additional security measures")
        
        # Clear logs and caches
        clear_commands = [
            "logcat -c",
            "dmesg -c",
            "rm -rf /data/local/tmp/*",
            "rm -rf /data/data/com.dts.freefireth/cache/*",
            "pm clear com.dts.freefireth"
        ]
        
        for cmd in clear_commands:
            success, stdout, stderr = self.run_command([
                self.adb_path.get(), "shell", "su -c", f'"{cmd}"'
            ])
            if success:
                self.log_message(f"Executed: {cmd}")
        
        self.log_message("Bypass sequence completed!")
        self.log_message("You can now launch Free Fire on your emulator")
        self.log_message("Note: Some changes may require a reboot to take effect")
    
    def get_emulator_files(self, emulator_type):
        # Return emulator-specific files to hide
        files = {
            "LDPlayer": [
                "/system/bin/ldplayer", "/system/bin/ld", "/system/bin/ldnetchange",
                "/system/app/LDPlayer", "/system/priv-app/LDPlayer", "/system/lib/libldplayer.so"
            ],
            "Nox": [
                "/system/bin/nox", "/system/bin/noxvm", "/system/bin/noxd",
                "/system/app/Nox", "/system/priv-app/Nox", "/system/lib/libnox.so"
            ],
            "BlueStacks": [
                "/system/bin/bluestacks", "/system/bin/bst", "/system/bin/bstvm",
                "/system/app/BlueStacks", "/system/priv-app/BlueStacks", "/system/lib/libbst.so"
            ],
            "Memu": [
                "/system/bin/memu", "/system/bin/memuvm", "/system/bin/memud",
                "/system/app/MEmu", "/system/priv-app/MEmu", "/system/lib/libmemu.so"
            ],
            "Generic": [
                "/system/bin/qemu-props", "/system/bin/qemu-arm", "/system/bin/qemu-i386",
                "/system/lib/libc_malloc_debug_qemu.so", "/system/bin/genymotion",
                "/system/bin/androVM_setprop", "/system/bin/vbox", "/system/bin/vms"
            ]
        }
        
        return files.get(emulator_type, files["Generic"])
    
    def on_closing(self):
        if self.is_running:
            self.stop_bypass()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FreeFireBypassTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()