import hashlib
import os
import logging
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox, scrolledtext
import time
import threading

# Set up logging - simple format 
logging.basicConfig(filename='integrity.log', level=logging.INFO, 
                   format='%(asctime)s - %(message)s')

class FileMonitor:
    """Handles the core file monitoring functionality"""
    def __init__(self):
        # Dictionary to store file paths and their hash values
        self.files = {}
        # Track which files have been modified since initial scan
        self.modified = set()
        self.is_running = False
        self.thread = None

    def get_hash(self, file_path):
        """Get SHA-256 hash of a file"""
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                chunk = f.read(4096)
                while chunk:
                    h.update(chunk)
                    chunk = f.read(4096)
            return h.hexdigest()
        except FileNotFoundError:
            # File doesn't exist or was deleted
            logging.error(f"Can't find file: {file_path}")
            return None
        except PermissionError:
            # No permission to read file
            logging.error(f"Access denied: {file_path}")
            return None
        except:
            # Catch any other errors
            logging.error(f"Error reading {file_path}")
            return None

    def check_file(self, path):
        """Check if a file's hash has changed"""
        hash = self.get_hash(path)
        
        if not hash:  # Failed to get hash
            return False, f"Error: Couldn't read {path}"
            
        if path in self.files:
            # We've seen this file before
            if self.files[path] != hash:
                # Hash has changed - file was modified
                self.modified.add(path)
                self.files[path] = hash  # Update with new hash
                msg = f"WARNING! File changed: {path}"
                logging.warning(msg)
                print(msg)  # Also print to console
                return False, msg
            elif path in self.modified:
                # File was modified previously
                return False, f"Failed integrity check: {path} (previously modified)"
            else:
                # File is unchanged
                return True, f"File OK: {path}"
        else:
            # First time seeing this file - add to monitored files
            self.files[path] = hash
            logging.info(f"Now monitoring: {path}")
            return True, f"Added new file: {path}"

    def scan_directory(self, dir_path):
        """Check all files in a directory and its subdirectories"""
        results = []
        
        # Make sure directory exists
        if not os.path.isdir(dir_path):
            msg = f"Directory not found: {dir_path}"
            logging.error(msg)
            results.append(msg)
            return results
        
        # Walk through directory tree
        for folder, _, filenames in os.walk(dir_path):
            for fname in filenames:
                full_path = os.path.join(folder, fname)
                _, msg = self.check_file(full_path)
                results.append(msg)
        
        return results
    
    # Simple getters for UI to show stats
    def total_files(self):
        return len(self.files)
    
    def changed_files(self):
        return len(self.modified)


# The main application class
class IntegrityMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor Tool")
        # Better size for most screens
        self.root.geometry("850x550")
        
        # Create file monitor instance
        self.file_monitor = FileMonitor()
        
        # Keep track of paths being monitored
        self.paths = set()
        self.active = False
        # Hard-coded for now, could make configurable later
        self.check_interval = 5  
        
        # Build the GUI
        self.create_ui()
        
        # Update stats once at startup
        self.refresh_stats()

    def create_ui(self):
        """Create the application UI"""
        # Main container 
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Top section with app title and stats
        top = ttk.Frame(main)
        top.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(top, text="File Integrity Monitor", 
                 font=("Helvetica", 16, "bold")).pack(side=tk.LEFT)
        
        # Stats display on right side
        stats = ttk.Frame(top)
        stats.pack(side=tk.RIGHT)
        
        # Text variables for dynamic stats
        self.files_var = tk.StringVar(value="Files: 0")
        self.mod_var = tk.StringVar(value="Modified: 0")
        self.status_var = tk.StringVar(value="Status: Idle")
        
        # Display stats with some styling
        ttk.Label(stats, textvariable=self.files_var).pack(side=tk.LEFT, padx=5)
        self.mod_lbl = ttk.Label(stats, textvariable=self.mod_var, 
                                bootstyle="danger")
        self.mod_lbl.pack(side=tk.LEFT, padx=5)
        self.status_lbl = ttk.Label(stats, textvariable=self.status_var)
        self.status_lbl.pack(side=tk.LEFT, padx=5)
        
        # Button section
        buttons = ttk.Frame(main)
        buttons.pack(fill=tk.X, pady=(0, 10))
        
        # Action buttons
        self.add_btn = ttk.Button(buttons, text="Add Files/Folders", 
                                 command=self.add_path,
                                 bootstyle="success")
        self.add_btn.pack(side=tk.LEFT, padx=3)
        
        self.monitor_btn = ttk.Button(buttons, text="Start Monitoring", 
                                     command=self.toggle_monitoring,
                                     bootstyle="primary")
        self.monitor_btn.pack(side=tk.LEFT, padx=3)
        
        ttk.Button(buttons, text="Clear Log", 
                  command=self.clear_log).pack(side=tk.LEFT, padx=3)
        
        # Log display area
        log_frame = ttk.LabelFrame(main, text="Monitoring Log")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollable text area for log
        self.log = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD,
            background="#1a1a1a", 
            foreground="#cccccc",
            font=("Consolas", 9)
        )
        self.log.pack(fill=tk.BOTH, expand=True)
        
        # Set up text tags for colorizing log entries
        self.log.tag_config("error", foreground="red")
        self.log.tag_config("ok", foreground="green")
        self.log.tag_config("warn", foreground="orange")
        self.log.tag_config("info", foreground="white")
        
        # Add some initial messages
        self.add_log("File Integrity Monitor started", "info")
        self.add_log("Add some files or folders to get started", "info")
        
        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self.quit_app)

    def add_path(self):
        """Open dialog to add file or directory"""
        # Try to get a file first
        path = filedialog.askopenfilename()
        if path:
            self.paths.add(path)
            ok, msg = self.file_monitor.check_file(path)
            tag = "ok" if ok else "error"
            self.add_log(msg, tag)
            self.refresh_stats()
            return
        
        # If no file was selected, try for a directory
        path = filedialog.askdirectory()
        if path:
            self.paths.add(path)
            self.add_log(f"Added folder: {path}", "info")
            # Check all files in the directory
            results = self.file_monitor.scan_directory(path)
            for msg in results:
                if "WARNING" in msg or "Failed" in msg:
                    tag = "error"
                elif "OK" in msg:
                    tag = "ok"
                else:
                    tag = "info"
                self.add_log(msg, tag)
            self.refresh_stats()

    def toggle_monitoring(self):
        """Start or stop continuous monitoring"""
        if not self.active:
            # Nothing to monitor yet
            if not self.paths:
                messagebox.showwarning("Warning", "Please add files or folders first!")
                return
                
            # Start monitoring
            self.active = True
            self.monitor_btn.config(text="Stop Monitoring", bootstyle="danger")
            self.status_var.set("Status: Monitoring")
            self.status_lbl.configure(bootstyle="success")
            
            # Run monitoring in background
            self.thread = threading.Thread(target=self.run_monitoring)
            self.thread.daemon = True  # Thread will exit when main app exits
            self.thread.start()
            
            self.add_log(f"Started continuous monitoring (every {self.check_interval} seconds)", "info")
        else:
            # Stop monitoring
            self.active = False
            self.monitor_btn.config(text="Start Monitoring", bootstyle="primary")
            self.status_var.set("Status: Idle")
            self.status_lbl.configure(bootstyle="secondary")
            self.add_log("Monitoring stopped", "info")

    def run_monitoring(self):
        """Continuously check files at regular intervals"""
        while self.active:
            changes = False  # Track if we found any changes this cycle
            
            # Show start of check cycle
            curr_time = time.strftime("%H:%M:%S")
            self.safe_log(f"Checking files at {curr_time}", "info")
            
            # Check all monitored paths
            for path in self.paths:
                if os.path.isdir(path):
                    results = self.file_monitor.scan_directory(path)
                    for msg in results:
                        if "WARNING" in msg or "Failed" in msg:
                            self.safe_log(msg, "error")
                            changes = True
                        elif "OK" in msg:
                            # Don't log unchanged files to reduce noise
                            pass
                        else:
                            self.safe_log(msg, "info")
                else:  # It's a file
                    ok, msg = self.file_monitor.check_file(path)
                    if not ok:
                        self.safe_log(msg, "error")
                        changes = True
            
            # Update stats display
            self.root.after(0, self.refresh_stats)
            
            # Add a separator if we found changes
            if changes:
                self.safe_log("-" * 40, "warn")
            
            # Wait before next check
            time.sleep(self.check_interval)

    def safe_log(self, message, tag="info"):
        """Update log from a background thread"""
        self.root.after(0, lambda: self.add_log(message, tag))

    def add_log(self, message, tag="info"):
        """Add a message to the log display"""
        # Add timestamp
        t = time.strftime("%H:%M:%S")
        self.log.insert(tk.END, f"[{t}] ", "info")
        self.log.insert(tk.END, f"{message}\n", tag)
        # Scroll to bottom
        self.log.see(tk.END)
        
    def clear_log(self):
        """Clear the log display"""
        self.log.delete(1.0, tk.END)
        self.add_log("Log cleared", "info")
    
    def refresh_stats(self):
        """Update the statistics display"""
        total = self.file_monitor.total_files()
        modified = self.file_monitor.changed_files()
        
        self.files_var.set(f"Files: {total}")
        self.mod_var.set(f"Modified: {modified}")
        
    def quit_app(self):
        """Handle application exit"""
        if self.active:
            self.active = False
            # Give thread time to stop
            time.sleep(0.2)
        self.root.destroy()

# Program entry point
if __name__ == "__main__":
    # Use darkly theme from ttkbootstrap
    root = ttk.Window(themename="darkly")
    app = IntegrityMonitorApp(root)
    root.mainloop()