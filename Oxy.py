import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
import time

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OxyCrypt Pro - AES-256 File Encryption")
        self.root.geometry("600x450")
        self.root.resizable(False, False)
        self.root.minsize(800, 650)
        
        # Setup modern dark theme colors
        self.bg_color = "#121212"
        self.card_color = "#1e1e1e"
        self.accent_color = "#00bcd4"  # Teal accent
        self.button_color = "#2196f3"   # Blue
        self.decrypt_color = "#B35C58"  # Purple
        self.text_color = "#e0e0e0"
        self.danger_color = "#f44336"
        self.success_color = "#4caf50"
        
        # Configure root background
        self.root.configure(bg=self.bg_color)
        
        # Create widgets
        self.create_widgets()
        
        # Initialize threading lock
        self.lock = threading.Lock()
        
        # Track file selection
        self.selected_file = None
        
    def create_widgets(self):
        # Configure styles
        self.configure_styles()
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.bg_color, padx=20, pady=20)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header section
        header_frame = tk.Frame(main_container, bg=self.bg_color)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(
            header_frame, 
            text="🔒 OxyCrypt Pro", 
            font=("Segoe UI", 20, "bold"),
            fg=self.accent_color,
            bg=self.bg_color
        ).pack(side=tk.LEFT)
        
        tk.Label(
            header_frame, 
            text="AES-256 File Encryption", 
            font=("Segoe UI", 11),
            fg=self.text_color,
            bg=self.bg_color
        ).pack(side=tk.LEFT, padx=(10, 0), pady=(5, 0))
        
        # File selection card
        file_card = ttk.LabelFrame(
            main_container, 
            text=" File Selection ",
            padding=(20, 15),
            style="Card.TLabelframe"
        )
        file_card.pack(fill=tk.X, pady=(0, 15))
        
        # File path display
        self.file_label = tk.Label(
            file_card, 
            text="No file selected",
            font=("Segoe UI", 9),
            fg="#bbbbbb",
            bg=self.card_color,
            anchor=tk.W,
            wraplength=400
        )
        self.file_label.pack(fill=tk.X, padx=5, pady=(0, 10))
        
        # File selection button
        file_btn_frame = tk.Frame(file_card, bg=self.card_color)
        file_btn_frame.pack(fill=tk.X)
        
        ttk.Button(
            file_btn_frame,
            text="Browse Files",
            command=self.select_file,
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            file_btn_frame,
            text="Clear Selection",
            command=self.clear_file_selection,
            style="Secondary.TButton"
        ).pack(side=tk.LEFT)
        
        # Security card
        security_card = ttk.LabelFrame(
            main_container, 
            text=" Security Settings ",
            padding=(20, 15),
            style="Card.TLabelframe"
        )
        security_card.pack(fill=tk.X, pady=(0, 15))
        
        # Password entry
        pass_frame = tk.Frame(security_card, bg=self.card_color)
        pass_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(
            pass_frame, 
            text="Password:", 
            font=("Segoe UI", 10),
            bg=self.card_color,
            fg=self.text_color
        ).pack(anchor=tk.W, pady=(0, 5))
        
        self.password_entry = tk.Entry(
            pass_frame, 
            show="•", 
            width=40,
            font=("Segoe UI", 11),
            bg="#252525",
            fg=self.text_color,
            insertbackground="white",
            relief=tk.FLAT
        )
        self.password_entry.pack(fill=tk.X, padx=5, pady=5, ipady=3)
        
        # Password visibility toggle
        pass_toggle_frame = tk.Frame(security_card, bg=self.card_color)
        pass_toggle_frame.pack(fill=tk.X)
        
        self.show_pass = tk.BooleanVar(value=False)
        pass_toggle = tk.Checkbutton(
            pass_toggle_frame, 
            text="Show Password",
            variable=self.show_pass,
            command=self.toggle_password_visibility,
            bg=self.card_color,
            fg=self.text_color,
            selectcolor="#252525",
            activebackground=self.card_color,
            activeforeground=self.text_color,
            font=("Segoe UI", 9)
        )
        pass_toggle.pack(side=tk.LEFT)
        
        # Options card
        options_card = ttk.LabelFrame(
            main_container, 
            text=" Options ",
            padding=(20, 15),
            style="Card.TLabelframe"
        )
        options_card.pack(fill=tk.X, pady=(0, 15))
        
        # Overwrite option
        self.overwrite_var = tk.BooleanVar(value=False)
        overwrite_check = tk.Checkbutton(
            options_card, 
            text="Overwrite original file",
            variable=self.overwrite_var,
            bg=self.card_color,
            fg=self.text_color,
            selectcolor="#252525",
            activebackground=self.card_color,
            activeforeground=self.text_color,
            font=("Segoe UI", 9)
        )
        overwrite_check.pack(anchor=tk.W)
        
        # Action buttons
        action_frame = tk.Frame(main_container, bg=self.bg_color)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Encrypt button
        encrypt_btn = ttk.Button(
            action_frame,
            text="Encrypt File",
            command=self.encrypt_action,
            style="Primary.TButton",
            width=15
        )
        encrypt_btn.pack(side=tk.LEFT, padx=(0, 15))
        
        # Decrypt button
        decrypt_btn = ttk.Button(
            action_frame,
            text="Decrypt File",
            command=self.decrypt_action,
            style="Decrypt.TButton",
            width=15
        )
        decrypt_btn.pack(side=tk.LEFT)
        
        # Center buttons
        action_frame.pack_propagate(False)
        action_frame.configure(height=50)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            main_container, 
            orient=tk.HORIZONTAL, 
            length=400, 
            mode='determinate',
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress.pack(fill=tk.X, pady=(15, 5))
        
        # Status area
        status_frame = tk.Frame(main_container, bg=self.bg_color)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_var = tk.StringVar(value="Ready. Select a file to begin.")
        self.status_label = tk.Label(
            status_frame, 
            textvariable=self.status_var,
            font=("Segoe UI", 9),
            bg=self.bg_color,
            fg="#aaaaaa"
        )
        self.status_label.pack(side=tk.LEFT)
        
        # Operation time
        self.time_var = tk.StringVar(value="")
        time_label = tk.Label(
            status_frame, 
            textvariable=self.time_var,
            font=("Segoe UI", 9),
            bg=self.bg_color,
            fg="#777777"
        )
        time_label.pack(side=tk.RIGHT)
    
    def configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure card style
        style.configure("Card.TLabelframe", 
                        background=self.card_color, 
                        foreground=self.text_color,
                        bordercolor="#333333",
                        lightcolor=self.card_color,
                        darkcolor=self.card_color,
                        relief=tk.RAISED,
                        font=("Segoe UI", 9, "bold"))
        
        style.configure("Card.TLabelframe.Label", 
                       background=self.card_color, 
                       foreground=self.accent_color)
        
        # Button styles
        style.configure("Primary.TButton", 
                       background=self.button_color, 
                       foreground="white",
                       font=("Segoe UI", 10, "bold"),
                       borderwidth=1,
                       focusthickness=0,
                       focuscolor=self.card_color,
                       padding=8)
        
        style.map("Primary.TButton",
                  background=[('active', '#1976d2'), ('pressed', '#0d47a1')])
        
        style.configure("Decrypt.TButton", 
                       background=self.decrypt_color, 
                       foreground="white",
                       font=("Segoe UI", 10, "bold"),
                       borderwidth=1,
                       focusthickness=0,
                       focuscolor=self.card_color,
                       padding=8)
        
        style.map("Decrypt.TButton",
                  background=[('active', '#89261B'), ('pressed', '#EF233C')])
        
        style.configure("Accent.TButton", 
                       background=self.accent_color, 
                       foreground="white",
                       font=("Segoe UI", 9, "bold"),
                       borderwidth=0,
                       focusthickness=0,
                       focuscolor=self.card_color,
                       padding=6)
        
        style.map("Accent.TButton",
                  background=[('active', '#0097a7'), ('pressed', '#006064')])
        
        style.configure("Secondary.TButton", 
                       background="#424242", 
                       foreground=self.text_color,
                       font=("Segoe UI", 9),
                       borderwidth=0,
                       focusthickness=0,
                       focuscolor=self.card_color,
                       padding=6)
        
        style.map("Secondary.TButton",
                  background=[('active', '#616161'), ('pressed', '#212121')])
        
        # Progress bar style
        style.configure("Custom.Horizontal.TProgressbar", 
                       thickness=6, 
                       troughcolor="#2d2d2d",
                       background=self.accent_color,
                       bordercolor="#333333",
                       lightcolor=self.accent_color,
                       darkcolor=self.accent_color)
    
    def toggle_password_visibility(self):
        if self.show_pass.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def select_file(self):
        self.selected_file = filedialog.askopenfilename(
            title="Select File",
            filetypes=(
                ("All files", "*.*"),
                ("Documents", "*.txt *.doc *.docx *.pdf *.rtf"),
                ("Images", "*.jpg *.jpeg *.png *.bmp *.gif"),
                ("Media", "*.mp3 *.mp4 *.avi *.mov"),
                ("Archives", "*.zip *.rar *.7z *.tar.gz"),
                ("Encrypted", "*.enc")
            )
        )
        if self.selected_file:
            file_name = os.path.basename(self.selected_file)
            file_size = os.path.getsize(self.selected_file) / (1024 * 1024)  # in MB
            self.file_label.config(
                text=f"{file_name} ({file_size:.2f} MB)",
                fg=self.text_color
            )
            self.status_var.set(f"Selected: {file_name}")
    
    def clear_file_selection(self):
        self.selected_file = None
        self.file_label.config(text="No file selected", fg="#bbbbbb")
        self.status_var.set("Ready. Select a file to begin.")
    
    def encrypt_action(self):
        if not self.selected_file:
            messagebox.showwarning("Selection Required", "Please select a file first")
            return
            
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password")
            return
            
        overwrite = self.overwrite_var.get()
        self.start_operation(self.encrypt_file, self.selected_file, password, overwrite)
    
    def decrypt_action(self):
        if not self.selected_file:
            messagebox.showwarning("Selection Required", "Please select a file first")
            return
            
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password")
            return
            
        overwrite = self.overwrite_var.get()
        self.start_operation(self.decrypt_file, self.selected_file, password, overwrite)
    
    def start_operation(self, func, *args):
        """Start encryption/decryption in a separate thread"""
        self.progress["value"] = 0
        self.status_var.set("Starting operation...")
        self.time_var.set("")
        self.root.update()
        
        # Disable UI during operation
        for widget in self.root.winfo_children():
            if isinstance(widget, (ttk.Button, tk.Button)):
                widget.config(state=tk.DISABLED)
        
        # Record start time
        self.start_time = time.time()
        
        # Run in background thread
        threading.Thread(
            target=self.run_threaded, 
            args=(func, *args), 
            daemon=True
        ).start()
        
        # Start progress animation
        self.animate_progress()
    
    def animate_progress(self):
        """Animate progress bar while operation is running"""
        if self.progress["value"] < 90:
            self.progress["value"] += 5
            self.root.after(100, self.animate_progress)
    
    def run_threaded(self, func, *args):
        """Run function in thread and handle UI updates"""
        try:
            result = func(*args)
            self.root.after(0, self.operation_complete, True, result)
        except Exception as e:
            self.root.after(0, self.operation_complete, False, str(e))
    
    def operation_complete(self, success, result):
        """Handle completion of encryption/decryption"""
        # Complete progress animation
        self.progress["value"] = 100
        
        # Calculate operation time
        elapsed = time.time() - self.start_time
        self.time_var.set(f"Time: {elapsed:.2f}s")
        
        # Re-enable UI
        for widget in self.root.winfo_children():
            if isinstance(widget, (ttk.Button, tk.Button)):
                widget.config(state=tk.NORMAL)
        
        if success:
            self.status_var.set("Operation completed successfully")
            self.status_label.config(fg=self.success_color)
            messagebox.showinfo("Success", result)
            
            # Clear selection after successful operation
            if self.overwrite_var.get():
                self.clear_file_selection()
        else:
            self.status_var.set("Operation failed")
            self.status_label.config(fg=self.danger_color)
            messagebox.showerror("Error", result)
        
        # Reset status color after delay
        self.root.after(3000, lambda: self.status_label.config(fg="#aaaaaa"))
        
        # Clear password field
        self.password_entry.delete(0, tk.END)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Key derivation using PBKDF2HMAC with SHA-256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # Increased for better security
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_file(self, file_path, password, overwrite=False):
        """Encrypt file with AES-256 and save with .enc extension"""
        try:
            # Get file size for progress simulation
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            salt = os.urandom(16)  # Secure random salt
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)
            
            # Determine output path
            if overwrite:
                output_path = file_path
            else:
                output_path = file_path + ".enc"
            
            with open(output_path, 'wb') as f:
                f.write(salt + encrypted)
            
            # Clean up original if overwriting
            if overwrite and output_path != file_path:
                os.remove(file_path)
            
            return f"File encrypted successfully: {os.path.basename(output_path)}"
        
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, file_path, password, overwrite=False):
        """Decrypt AES-256 encrypted file"""
        try:
            # Get file size for progress simulation
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            salt = content[:16]
            encrypted_data = content[16:]
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            
            try:
                decrypted = fernet.decrypt(encrypted_data)
            except InvalidToken:
                raise Exception("Decryption failed. Wrong password or corrupted file.")
            
            # Determine output path
            if overwrite:
                output_path = file_path
                # Remove .enc extension if present
                if file_path.endswith('.enc'):
                    output_path = file_path[:-4]
            else:
                # Remove .enc extension or add _decrypted
                if file_path.endswith('.enc'):
                    output_path = file_path[:-4] + "_decrypted"
                else:
                    output_path = file_path + "_decrypted"
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            # Clean up encrypted file if overwriting
            if overwrite and output_path != file_path:
                os.remove(file_path)
            
            return f"File decrypted successfully: {os.path.basename(output_path)}"
        
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()