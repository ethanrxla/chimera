#!/usr/bin/env python3
"""
WhiteHat Launcher
This script provides a unified interface to access all the tools and resources
integrated into the WhiteHat project.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import threading
from datetime import datetime
import webbrowser
import random
import time
import math
import asyncio
from test_finetuned_model import generate_response
from ai_agent import StarGuardAgent, LoraV2Agent, MalwareAnalysisAgent, SecurityToolsAgent, SecurityReposAgent

# Define paths
PROJECT_ROOT = Path("D:/whitehat")
HACKINGTOOL_PATH = Path("D:/whitehat/starcoder/hackingtool")
AWESOME_HACKING_PATH = Path("D:/whitehat/Awesome-Hacking")
CYBERSEC_REPOS_PATH = Path("D:/whitehat/cybersec_repos")
MODEL_PATH = Path("D:/whitehat/model_outputs/codegen-cybersec-ultimate-v2")  # Default model

# Add the hackingtool directory to the Python path
sys.path.append(str(HACKINGTOOL_PATH.absolute()))

# Set max token limit for all models
MAX_TOKENS = 2048

class ModernTheme:
    """Toxic cyberpunk theme with blood red accents"""
    BG_DARK = "#000000"  # Pure black
    BG_MEDIUM = "#0a0a0a"  # Very dark gray
    BG_LIGHT = "#1a1a1a"  # Dark gray
    FG_DARK = "#ff0000"  # Blood red
    FG_LIGHT = "#ff1a1a"  # Lighter blood red
    ACCENT = "#ff0000"  # Blood red
    ACCENT_HOVER = "#cc0000"  # Darker blood red
    ERROR = "#ff0000"  # Pure red
    SUCCESS = "#ff1a1a"  # Light red
    WARNING = "#ff3366"  # Pink warning
    HEADER_FG = "#ff0000"  # Blood red
    TEXT_SHADOW = "#330000"  # Dark red shadow

class MatrixRain:
    def __init__(self, root):
        self.root = root
        self.canvas = tk.Canvas(
            root,
            bg='black',
            width=1200,
            height=800
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        # Matrix characters (using more hacker-style characters)
        self.matrix_chars = "ᚻᚫᚲᚴᛖᚱ01@#$%&*!?<>/\\[]{}|=+-_"
        self.streams = []
        self.is_running = True
        
        # Bind key '1' silently
        self.root.bind('1', self.stop_animation)
        
        # Keep the original toxic skull for the matrix rain
        self.canvas.create_text(
            600, 400,
            text="""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡖⠁⠀⠀⠀⠀⠀⠀⠈⢲⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣼⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣸⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⡇⠀⢀⣀⣤⣤⣤⣤⣀⡀⠀⢸⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣔⢿⡿⠟⠛⠛⠻⢿⡿⣢⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣿⣷⣤⣀⡀⢀⣀⣤⣾⣿⣿⣿⣷⣶⣤⡀⠀⠀⠀⠀
⠀⠀⢠⣾⣿⡿⠿⠿⠿⣿⣿⣿⣿⡿⠏⠻⢿⣿⣿⣿⣿⠿⠿⠿⢿⣿⣷⡀⠀⠀
⠀⢠⡿⠋⠁⠀⠀⢸⣿⡇⠉⠻⣿⠇⠀⠀⠸⣿⡿⠋⢰⣿⡇⠀⠀⠈⠙⢿⡄⠀
⠀⡿⠁⠀⠀⠀⠀⠘⣿⣷⡀⠀⠰⣿⣶⣶⣿⡎⠀⢀⣾⣿⠇⠀⠀⠀⠀⠈⢿⠀
⠀⡇⠀⠀⠀⠀⠀⠀⠹⣿⣷⣄⠀⣿⣿⣿⣿⠀⣠⣾⣿⠏⠀⠀⠀⠀⠀⠀⢸⠀
⠀⠁⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⢇⣿⣿⣿⣿⡸⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠈⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠐⢤⣀⣀⢀⣀⣠⣴⣿⣿⠿⠋⠙⠿⣿⣿⣦⣄⣀⠀⠀⣀⡠⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠉⠛⠛⠛⠛⠉⠀⠀⠀⠀⠀⠈⠉⠛⠛⠛⠛⠋⠁⠀⠀⠀⠀⠀
""",
            font=("Pirata One", 16),
            fill="#ff0000",
            anchor="center"
        )
        
        self.animate()

    def stop_animation(self, event=None):
        self.is_running = False
        self.canvas.destroy()
        self.root.unbind('1')
        # Launch the main interface
        WhiteHatLauncher(self.root)

    def animate(self):
        if not self.is_running:
            return
            
        self.canvas.delete("rain")
        
        # Increase stream creation chance and add more streams
        if random.random() < 0.3:  # Increased from 0.1
            for _ in range(3):  # Create multiple streams at once
                x = random.randint(0, 1200)
                self.streams.append({
                    "x": x, 
                    "y": 0, 
                    "speed": random.randint(5, 20),  # Increased max speed
                    "color": random.choice([
                        "#00ff41",  # Matrix green
                        "#cc00cc",  # Purple
                        "#990099",  # Darker purple
                        "#00cc00",  # Lighter green
                    ]),
                    "length": random.randint(5, 15)  # Variable stream length
                })
        
        # Update existing streams with more complex effects
        for stream in self.streams[:]:
            y = stream["y"]
            
            # Create longer trailing effect with variable length
            for i in range(stream["length"]):
                char = random.choice(self.matrix_chars)
                
                # Calculate fade based on position in stream
                fade = 1 - (i / stream["length"])
                opacity = int(255 * fade)
                color = stream["color"][:-2] + f"{opacity:02x}"
                
                # Add slight horizontal drift
                drift = math.sin(y/50) * 3
                x_pos = stream["x"] + drift
                
                # Create main character and shadow effect
                self.canvas.create_text(
                    x_pos, y - i*15,
                    text=char,
                    font=("Courier New", 14),
                    fill=color,
                    tags="rain"
                )
                
                # Random bright flashes
                if random.random() < 0.05:
                    self.canvas.create_text(
                        x_pos, y - i*15,
                        text=char,
                        font=("Courier New", 14),
                        fill="#ffffff",
                        tags="rain"
                    )
            
            stream["y"] += stream["speed"]
            
            if stream["y"] > 800:
                self.streams.remove(stream)
        
        self.root.after(40, self.animate)  # Slightly faster update rate

class WhiteHatLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("BlackBeard Security Suite")
        self.root.geometry("1200x800")  # Larger default size
        self.root.minsize(1200, 800)
        
        # Initialize status_var early
        self.status_var = tk.StringVar()
        
        # Load Myopium font
        self.root.option_add("*Font", "Myopium")
        
        # Configure the theme
        self.configure_theme()
        
        # Set window background
        self.root.configure(bg=ModernTheme.BG_DARK)
        
        # Create main container with matrix background
        self.main_container = ttk.Frame(root, style="Matrix.TFrame")
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create sidebar
        self.create_sidebar()
        
        # Create main content area
        self.content_frame = ttk.Frame(self.main_container, style="Matrix.TFrame")
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Initialize the home screen
        self.show_home()
        
        # Create the status bar
        self.create_status_bar()
        
        # Verify components
        self.verify_components()
        
        # Map UI model names to actual model paths
        self.model_mapping = {
            "STARGUARD": "codegen-cybersec-ultimate-v2",
            "TOOLS": "codegen-cybersec-final-tools", 
            "REPOS": "codegen-cybersec-repos",
            "LORA-V2": "codegen-cybersec-lora-v2",
            "MALWARE": "codegen-cybersec-malwarebazaar"  # Verify this mapping
        }
        self.full_responses = {}  # Store full responses by timestamp
    
    def configure_theme(self):
        style = ttk.Style()
        
        # Configure main styles with pirate font
        style.configure(".", 
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.FG_DARK,
                       font=("Pirata One", 10))  # Pirate font
        
        # Matrix frame style
        style.configure("Matrix.TFrame",
                       background=ModernTheme.BG_DARK)
        
        # Matrix label style
        style.configure("Matrix.TLabel",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.FG_DARK,
                       font=("Courier New", 10))
        
        # Header label style with terminator font
        style.configure("Header.TLabel",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.HEADER_FG,
                       font=("BlackChancery", 24, "bold"))  # Medieval pirate font
        
        # Subheader label style
        style.configure("Subheader.TLabel",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.FG_DARK,
                       font=("Courier New", 12))
        
        # Matrix button style
        style.configure("Matrix.TButton",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.FG_DARK,
                       font=("Courier New", 10, "bold"),
                       padding=10,
                       borderwidth=2,
                       relief="raised")
        
        style.map("Matrix.TButton",
                  background=[("active", ModernTheme.BG_LIGHT)],
                  foreground=[("active", ModernTheme.FG_LIGHT)])
        
        # Sidebar button style
        style.configure("Sidebar.TButton",
                       background=ModernTheme.BG_MEDIUM,
                       foreground=ModernTheme.FG_DARK,
                       font=("Courier New", 11, "bold"),
                       padding=15,
                       borderwidth=0)
        
        style.map("Sidebar.TButton",
                  background=[("active", ModernTheme.BG_LIGHT)],
                  foreground=[("active", ModernTheme.FG_LIGHT)])
    
    def create_sidebar(self):
        """Create the Matrix-styled sidebar"""
        sidebar = ttk.Frame(self.main_container, style="Matrix.TFrame")
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        
        # Logo with Myopium font
        logo_label = ttk.Label(
            sidebar,
            text="[ BLACKBEARD ]\n[ SECURITY ]",
            font=("Myopium", 24, "bold"),
            foreground=ModernTheme.FG_DARK,
            background=ModernTheme.BG_DARK,
            justify=tk.CENTER
        )
        logo_label.pack(pady=(0, 20))
        
        # Create navigation buttons
        nav_buttons = [
            ("[ 🏠 HOME ]", self.show_home),
            ("[ 🛠️ TOOLS ]", self.show_hacking_tools),
            ("[ 🤖 STARGUARD ]", self.show_starguard),
            ("[ 👥 AGENTS ]", self.show_agents),
            ("[ 📚 DOCS ]", self.show_resources),
            ("[ ⚙️ CONFIG ]", self.show_settings)
        ]
        
        for text, command in nav_buttons:
            btn = ttk.Button(
                sidebar,
                text=text,
                command=command,
                style="Sidebar.TButton"
            )
            btn.pack(fill=tk.X, pady=5)
    
    def clear_content(self):
        """Clear the content frame"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def show_home(self):
        """Show the BlackBeard-styled home screen"""
        self.clear_content()
        
        # Create banner frame
        banner_frame = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        banner_frame.pack(pady=20)
        
        # Sophisticated skull and crossbones
        skull_art = ttk.Label(
            banner_frame,
            text="""
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⠻⣿⣿⣿⣿⣿⣿⣷⡀⢸⣿⣷⠀⠀⣾⣿⡇⢀⣾⣿⣿⣿⣿⣿⣿⠟⣿⣿
⣿⣿⡆⠙⣿⣿⣿⣿⣿⣿⣄⠈⠛⠋⡰⢆⠙⠛⠁⣠⣿⣿⣿⣿⣿⣿⠋⢰⣿⣿
⣿⣿⣿⡀⠈⠻⣿⣿⣿⣿⣿⣿⣦⣤⣤⣤⣤⣴⣿⣿⣿⣿⣿⣿⠟⠁⢀⣿⣿⣿
⣿⣿⣿⣷⡀⠀⠘⢿⣿⣿⣿⡇⠘⢿⣿⣿⡿⠃⢸⣿⣿⣿⡿⠃⠀⢀⣾⣿⣿⣿
⣿⣿⣿⣿⣷⣄⠀⠀⠙⠿⣿⣿⣦⣀⠈⠁⣀⣴⣿⣿⠿⠋⠀⠀⣠⣾⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠈⠻⢿⣿⣿⣿⣿⡿⠟⠁⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⣀⣭⡿⠟⠉⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣏⡉⢻⣿⠟⠋⠁⠀⠀⢀⣠⣴⣿⡟⢉⣹⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⠿⣿⠿⠛⢷⡄⠹⣇⣀⣠⣴⣾⣟⣉⣸⠏⢠⡾⠛⠿⣿⠿⣿⣿⣿⣿
⣿⣿⣿⡇⠀⢸⣧⣤⣾⣿⣄⣹⣿⣿⣿⣿⣿⣿⣏⣠⣿⣷⣤⣼⡇⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
""",
            font=("Courier New", 10),
            foreground=ModernTheme.FG_DARK,
            justify=tk.CENTER
        )
        skull_art.pack(pady=20)
        
        # Title with Myopium font
        title = ttk.Label(
            self.content_frame,
            text="[ BLACKBEARD SECURITY SUITE ]",
            font=("Myopium", 32, "bold"),
            foreground=ModernTheme.FG_DARK,
            background=ModernTheme.BG_DARK
        )
        title.pack(pady=20)
        
        # Create description
        desc = ttk.Label(
            self.content_frame,
            text="[ INTEGRATED SECURITY TOOLKIT FOR ETHICAL HACKERS ]",
            style="Subheader.TLabel",
            justify=tk.CENTER,
            wraplength=700
        )
        desc.pack(pady=20)
        
        # Create quick access buttons with Matrix styling
        quick_access = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        quick_access.pack(pady=30)
        
        tools = [
            ("[ LAUNCH HACKINGTOOL ]", self.run_hackingtool),
            ("[ STARGUARD 1.1 ]", self.show_starguard),
            ("[ BROWSE RESOURCES ]", self.show_resources)
        ]
        
        for text, command in tools:
            btn = ttk.Button(
                quick_access,
                text=text,
                command=command,
                style="Matrix.TButton"
            )
            btn.pack(side=tk.LEFT, padx=15)
    
    def show_hacking_tools(self):
        """Show the hacking tools interface"""
        self.clear_content()
        
        # Create tools grid
        tools_frame = ttk.Frame(self.content_frame)
        tools_frame.pack(fill=tk.BOTH, expand=True)
        
        tools = [
            {
                "name": "🛡️ Hackingtool",
                "description": "All-in-one hacking toolkit",
                "command": self.run_hackingtool
            },
            {
                "name": "🔍 Vulnerability Scanner",
                "description": "Scan systems for vulnerabilities",
                "command": self.run_vuln_scanner
            },
            {
                "name": "🌐 Network Tools",
                "description": "Network analysis and monitoring",
                "command": self.run_network_tools
            },
            {
                "name": "🔒 Crypto Tools",
                "description": "Cryptography and encryption tools",
                "command": self.run_crypto_tools
            }
        ]
        
        for i, tool in enumerate(tools):
            tool_frame = ttk.Frame(tools_frame)
            tool_frame.grid(row=i//2, column=i%2, padx=10, pady=10, sticky="nsew")
            
            name = ttk.Label(tool_frame, text=tool["name"], font=("Arial", 14, "bold"))
            name.pack(pady=5)
            
            desc = ttk.Label(tool_frame, text=tool["description"], wraplength=200)
            desc.pack(pady=5)
            
            btn = ttk.Button(tool_frame, text="Launch", command=tool["command"])
            btn.pack(pady=10)
    
    def show_starguard(self):
        """Show the Matrix-styled AI assistant interface"""
        self.clear_content()
        
        # Create chat interface
        chat_frame = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        chat_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = ttk.Label(
            chat_frame,
            text="[ STARGUARD 1.1 ]",
            style="Header.TLabel"
        )
        title.pack(pady=(0, 20))

        # Model selection tabs
        self.tab_control = ttk.Notebook(chat_frame)
        
        # Create tabs for each model
        self.model_tabs = {}
        models = {
            "STARGUARD": "D:/whitehat/model_outputs/codegen-cybersec-ultimate-v2",
            "LORA-V2": "D:/whitehat/model_outputs/codegen-cybersec-lora-v2",
            "MALWARE": "D:/whitehat/model_outputs/codegen-cybersec-malwarebazaar",
            "REPOS": "D:/whitehat/model_outputs/codegen-cybersec-repos", 
            "TOOLS": "D:/whitehat/model_outputs/codegen-cybersec-final-tools"
        }
        
        for model_name, model_path in models.items():
            tab = ttk.Frame(self.tab_control)
            self.tab_control.add(tab, text=model_name)
            self.model_tabs[model_name] = {
                "frame": tab,
                "path": model_path,
                "chat_history": scrolledtext.ScrolledText(
                    tab,
                    wrap=tk.WORD,
                    height=20,
                    bg=ModernTheme.BG_MEDIUM,
                    fg=ModernTheme.FG_DARK,
                    font=("Courier New", 10),
                    insertbackground=ModernTheme.FG_DARK
                )
            }
            self.model_tabs[model_name]["chat_history"].pack(fill=tk.BOTH, expand=True, pady=10)
            
        self.tab_control.pack(fill=tk.BOTH, expand=True)
        # Bind tab change event
        self.tab_control.bind('<<NotebookTabChanged>>', lambda e: self.switch_model(
            self.tab_control.tab(self.tab_control.select(), "text")
        ))
        
        # Input area with Matrix styling
        input_frame = ttk.Frame(chat_frame, style="Matrix.TFrame")
        input_frame.pack(fill=tk.X, pady=10)
        
        # Command prompt style input
        prompt_label = ttk.Label(
            input_frame,
            text="[ INPUT ] >",
            style="Matrix.TLabel"
        )
        prompt_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.chat_input = tk.Entry(
            input_frame,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            insertbackground=ModernTheme.FG_DARK,
            font=("Courier New", 10),
            relief="sunken",
            bd=2
        )
        self.chat_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        send_btn = ttk.Button(
            input_frame,
            text="[ SEND ]",
            command=self.send_to_ai,
            style="Matrix.TButton"
        )
        send_btn.pack(side=tk.RIGHT)
    
    def send_to_ai(self):
        """Send user input to AI model and display response"""
        message = self.chat_input.get()
        if message:
            # Clear input
            self.chat_input.delete(0, tk.END)
            
            # Get current model name and map to actual model path
            ui_model_name = self.tab_control.tab(self.tab_control.select(), "text")
            model_name = self.model_mapping.get(ui_model_name, "codegen-cybersec-ultimate-v2")
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            # Add user message to chat
            self.add_to_chat("User", message, ui_model_name)
            
            try:
                # Print to terminal for debugging/full view
                print("\n" + "="*50)
                print(f"Model: {model_name}")
                print(f"Prompt: {message}")
                print("="*50)
                
                # Generate response for UI
                response, success = generate_response(model_name, message)
                
                if success:
                    # Print full response to terminal
                    print("\nResponse:")
                    print("-"*50)
                    print(response)
                    print("-"*50 + "\n")
                    
                    # Store and show response in UI
                    self.full_responses[timestamp] = response
                    truncated = response[:2048] + "... [truncated]" if len(response) > 2048 else response
                    self.add_to_chat("AI Assistant", truncated, ui_model_name)
                    
                    # Add "Show Full" button if response was truncated
                    if len(response) > 2048:
                        self.add_show_full_button(timestamp, ui_model_name)
                else:
                    self.add_to_chat("System", f"Error: {response}", ui_model_name, error=True)
                    
            except Exception as e:
                self.add_to_chat("System", f"Error: {str(e)}", ui_model_name, error=True)
    
    def add_to_chat(self, sender, message, model_name, error=False):
        """Add message to chat history with Matrix styling"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = "[ ERROR ]" if error else f"[ {sender.upper()} ]"
        chat_history = self.model_tabs[model_name]["chat_history"]
        chat_history.insert(tk.END, f"[{timestamp}] {prefix}: {message}\n\n")
        chat_history.see(tk.END)
        
        if error:
            self.status_var.set(f"[ ERROR ] {message}")
        else:
            self.status_var.set("[ SYSTEM READY ]")
    
    def get_ai_response(self, message, model_name):
        """Get response from AI model"""
        try:
            # Use test_finetuned_model.py directly
            model_script = "D:/whitehat/test_finetuned_model.py"
            
            # Get model path from tabs dictionary
            model_path = self.model_tabs[model_name]["path"]
            
            # Run the model with the message
            cmd = [
                sys.executable,
                model_script,
                "--prompt", message,
                "--model_path", model_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return f"Error: {result.stderr}"

            # Parse the response section
            output = result.stdout
            if "Response:" in output:
                response = output.split("Response:", 1)[1].strip()
                if "--------------------------------------------------" in response:
                    response = response.split("--------------------------------------------------")[1]
                return response.strip()
            
            return output.strip()
            
        except Exception as e:
            return f"Error accessing AI model: {str(e)}"
    
    def show_resources(self):
        """Show the resources interface"""
        self.clear_content()
        
        # Create resources grid
        resources_frame = ttk.Frame(self.content_frame)
        resources_frame.pack(fill=tk.BOTH, expand=True)
        
        resources = [
            {
                "name": "📚 Awesome Hacking",
                "description": "Curated hacking resources",
                "command": self.run_awesome_hacking_browser
            },
            {
                "name": "🎓 Training Materials",
                "description": "Learning resources and tutorials",
                "command": self.show_training_materials
            },
            {
                "name": "🔬 Research Papers",
                "description": "Security research papers",
                "command": self.show_research_papers
            },
            {
                "name": "🛠️ Tool Documentation",
                "description": "Documentation for all tools",
                "command": self.show_documentation
            }
        ]
        
        for i, resource in enumerate(resources):
            resource_frame = ttk.Frame(resources_frame)
            resource_frame.grid(row=i//2, column=i%2, padx=10, pady=10, sticky="nsew")
            
            name = ttk.Label(resource_frame, text=resource["name"], font=("Arial", 14, "bold"))
            name.pack(pady=5)
            
            desc = ttk.Label(resource_frame, text=resource["description"], wraplength=200)
            desc.pack(pady=5)
            
            btn = ttk.Button(resource_frame, text="Open", command=resource["command"])
            btn.pack(pady=10)
    
    def show_settings(self):
        """Show the settings interface"""
        self.clear_content()
        
        # Create settings form
        settings_frame = ttk.Frame(self.content_frame)
        settings_frame.pack(fill=tk.BOTH, expand=True)
        
        # Model settings
        model_frame = ttk.LabelFrame(settings_frame, text="AI Model Settings")
        model_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(model_frame, text="Model Path:").pack(pady=5)
        ttk.Entry(model_frame, textvariable=tk.StringVar(value=str(MODEL_PATH))).pack(fill=tk.X, padx=5)
        
        # Tool paths
        paths_frame = ttk.LabelFrame(settings_frame, text="Tool Paths")
        paths_frame.pack(fill=tk.X, pady=10)
        
        paths = [
            ("Hackingtool Path:", HACKINGTOOL_PATH),
            ("Awesome Hacking Path:", AWESOME_HACKING_PATH),
            ("Cybersec Repos Path:", CYBERSEC_REPOS_PATH)
        ]
        
        for label, path in paths:
            ttk.Label(paths_frame, text=label).pack(pady=5)
            ttk.Entry(paths_frame, textvariable=tk.StringVar(value=str(path))).pack(fill=tk.X, padx=5)
    
    def create_status_bar(self):
        """Create the Matrix-styled status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("[ SYSTEM READY ]")
        
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            style="Matrix.TLabel",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
    
    def verify_components(self):
        """Verify all components are present"""
        missing = []
        
        if not MODEL_PATH.exists():
            missing.append("AI Model")
        if not HACKINGTOOL_PATH.exists():
            missing.append("Hackingtool")
        if not AWESOME_HACKING_PATH.exists():
            missing.append("Awesome Hacking Repository")
        if not CYBERSEC_REPOS_PATH.exists():
            missing.append("Cybersecurity Repositories")
        
        if missing:
            self.status_var.set(f"Warning: Missing components: {', '.join(missing)}")
            messagebox.showwarning(
                "Missing Components",
                f"The following components are missing:\n\n{chr(8226)} " + f"\n{chr(8226)} ".join(missing)
            )
    
    def run_hackingtool(self):
        """Run the Hackingtool with validation"""
        self.status_var.set("Launching Hackingtool...")
        self.root.update()
        
        try:
            if not HACKINGTOOL_PATH.exists():
                raise FileNotFoundError(f"Hackingtool not found at {HACKINGTOOL_PATH}")
            
            os.chdir(HACKINGTOOL_PATH)
            
            if platform.system() == "Windows":
                subprocess.Popen(["start", "cmd", "/k", "python", "hackingtool.py"], shell=True)
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", "python3", "hackingtool.py"])
            
            self.status_var.set("Hackingtool launched successfully")
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to launch Hackingtool: {str(e)}")
        finally:
            os.chdir(PROJECT_ROOT)
    
    # Placeholder methods for additional tools
    def run_vuln_scanner(self):
        messagebox.showinfo("Coming Soon", "Vulnerability Scanner will be available in the next update.")
    
    def run_network_tools(self):
        messagebox.showinfo("Coming Soon", "Network Tools will be available in the next update.")
    
    def run_crypto_tools(self):
        messagebox.showinfo("Coming Soon", "Crypto Tools will be available in the next update.")
    
    def scan_training_materials(self):
        """Scan directories for training materials"""
        materials = {
            'datasets': [],
            'papers': [],
            'books': [],
            'tutorials': [],
            'courses': []
        }
        
        # Scan main datasets directory
        datasets_path = Path("D:/whitehat/datasets")
        if datasets_path.exists():
            materials['datasets'].extend([
                f"Training Dataset: {d.name}"
                for d in datasets_path.iterdir()
                if d.is_dir() or d.suffix in ['.csv', '.json', '.txt', '.db', '.sqlite']
            ])

        # Scan hacking tools as training datasets
        hackingtool_path = HACKINGTOOL_PATH
        if hackingtool_path.exists():
            # Scan tool source code
            materials['datasets'].extend([
                f"Tool Source: {d.name} (Python Code)"
                for d in hackingtool_path.glob('**/*.py')
                if 'test' not in d.name.lower() and 'setup' not in d.name.lower()
            ])
            
            # Scan tool documentation
            materials['datasets'].extend([
                f"Tool Documentation: {d.name}"
                for d in hackingtool_path.glob('**/*.md')
                if 'readme' in d.name.lower() or 'documentation' in d.name.lower()
            ])

        # Scan cybersec_repos for training materials and tools
        repos_path = Path("D:/whitehat/cybersec_repos")
        if repos_path.exists():
            for repo in repos_path.iterdir():
                if repo.is_dir():
                    # Add source code as training data
                    if any(f.suffix == '.py' for f in repo.glob('**/*.py')):
                        materials['datasets'].append(f"Security Code: {repo.name} (Python)")
                    if any(f.suffix == '.cpp' for f in repo.glob('**/*.cpp')):
                        materials['datasets'].append(f"Security Code: {repo.name} (C++)")
                    if any(f.suffix == '.go' for f in repo.glob('**/*.go')):
                        materials['datasets'].append(f"Security Code: {repo.name} (Go)")
                    
                    # Check for different types of content
                    if any((repo/'papers').glob('*.pdf')):
                        materials['papers'].extend([
                            f"Paper: {p.stem} ({repo.name})"
                            for p in (repo/'papers').glob('*.pdf')
                        ])
                    
                    if any((repo/'tutorials').glob('*')):
                        materials['tutorials'].extend([
                            f"Tutorial: {t.name} ({repo.name})"
                            for t in (repo/'tutorials').iterdir()
                            if t.is_dir() or t.suffix in ['.md', '.txt', '.pdf']
                        ])
                    
                    if any((repo/'books').glob('*.pdf')):
                        materials['books'].extend([
                            f"Book: {b.stem} ({repo.name})"
                            for b in (repo/'books').glob('*.pdf')
                        ])

        # Scan DeepLearningExamples
        dl_path = Path("D:/whitehat/DeepLearningExamples")
        if dl_path.exists():
            materials['tutorials'].extend([
                f"Deep Learning: {d.name}" 
                for d in dl_path.iterdir() 
                if d.is_dir()
            ])

        # Scan awesome-ml-for-cybersecurity
        ml_sec_path = Path("D:/whitehat/awesome-ml-for-cybersecurity")
        if ml_sec_path.exists():
            # Scan for papers
            materials['papers'].extend([
                f"ML Security: {f.stem}"
                for f in ml_sec_path.glob('**/*.pdf')
            ])
            # Scan for tutorials
            materials['tutorials'].extend([
                f"ML Tutorial: {d.name}"
                for d in ml_sec_path.glob('**/tutorials/*')
                if d.is_dir()
            ])

        # Scan llm-datasets
        llm_path = Path("D:/whitehat/llm-datasets")
        if llm_path.exists():
            materials['datasets'].extend([
                f"LLM Dataset: {d.name}"
                for d in llm_path.iterdir()
                if d.is_dir() or d.suffix in ['.csv', '.json', '.txt']
            ])

        # Add cybersecurity code dataset
        code_dataset = Path("D:/whitehat/cybersecurity_code_dataset.csv")
        if code_dataset.exists():
            materials['datasets'].append("Cybersecurity Code Examples Dataset")

        return materials

    def show_training_materials(self):
        """Show available training materials"""
        try:
            # Scan for materials
            materials = self.scan_training_materials()
            
            # Display in UI
            self.clear_content()
            
            # Create canvas with scrollbar
            canvas = tk.Canvas(
                self.content_frame,
                bg=ModernTheme.BG_DARK,
                highlightthickness=0
            )
            scrollbar = ttk.Scrollbar(
                self.content_frame,
                orient="vertical",
                command=canvas.yview
            )
            
            # Create container frame inside canvas
            container = ttk.Frame(canvas, style="Matrix.TFrame")
            
            # Configure canvas
            canvas.configure(yscrollcommand=scrollbar.set)
            
            # Pack scrollbar and canvas
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            # Create window in canvas
            canvas_window = canvas.create_window(
                (0, 0),
                window=container,
                anchor="nw",
                width=canvas.winfo_width()
            )
            
            # Add section headers and items
            for section, items in materials.items():
                header = ttk.Label(
                    container,
                    text=f"[ {section.upper()} ]",
                    style="Header.TLabel"
                )
                header.pack(pady=(20,10), anchor=tk.W)
                
                if items:
                    for item in items:
                        item_frame = ttk.Frame(container)
                        item_frame.pack(fill=tk.X, pady=2)
                        
                        item_label = ttk.Label(
                            item_frame,
                            text=f"• {item}",
                            style="Matrix.TLabel",
                            wraplength=800
                        )
                        item_label.pack(side=tk.LEFT, pady=2)
                        
                        # Add open button for items that can be opened
                        if any(p in item for p in ["Dataset:", "Security Tool:", "Deep Learning:", "Tool Source:", "Tool Documentation:", "Security Code:"]):
                            open_btn = ttk.Button(
                                item_frame,
                                text="[ OPEN ]",
                                style="Matrix.TButton",
                                command=lambda i=item: self.open_training_material(i)
                            )
                            open_btn.pack(side=tk.RIGHT)
                else:
                    empty_label = ttk.Label(
                        container,
                        text="No items found",
                        style="Matrix.TLabel"
                    )
                    empty_label.pack(pady=2, anchor=tk.W)
            
            # Update scroll region when container size changes
            def configure_scroll_region(event):
                canvas.configure(scrollregion=canvas.bbox("all"))
            
            container.bind('<Configure>', configure_scroll_region)
            
            # Handle canvas resize
            def on_canvas_resize(event):
                canvas.itemconfig(canvas_window, width=event.width)
            
            canvas.bind('<Configure>', on_canvas_resize)
            
            # Bind mousewheel to scroll
            def on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            
            canvas.bind_all("<MouseWheel>", on_mousewheel)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load training materials: {str(e)}")

    def open_training_material(self, item):
        """Open the selected training material"""
        try:
            if "Tool Source: " in item:
                tool_name = item.split("Tool Source: ")[1].split(" (Python Code)")[0]
                # Find the tool's Python files
                for py_file in HACKINGTOOL_PATH.glob(f'**/{tool_name}*.py'):
                    if platform.system() == "Windows":
                        os.startfile(str(py_file))
                    else:
                        subprocess.run(["xdg-open", str(py_file)])
            
            elif "Tool Documentation: " in item:
                doc_name = item.split("Tool Documentation: ")[1]
                # Find the documentation file
                for doc_file in HACKINGTOOL_PATH.glob(f'**/{doc_name}'):
                    if platform.system() == "Windows":
                        os.startfile(str(doc_file))
                    else:
                        subprocess.run(["xdg-open", str(doc_file)])
            
            elif "Security Code: " in item:
                repo_name = item.split("Security Code: ")[1].split(" (")[0]
                lang = item.split("(")[1].strip(")")
                repo_path = Path("D:/whitehat/cybersec_repos") / repo_name
                
                # Open the repository's source code directory
                if platform.system() == "Windows":
                    os.startfile(str(repo_path))
                else:
                    subprocess.run(["xdg-open", str(repo_path)])
            
            elif "Training Dataset: " in item:
                path = Path("D:/whitehat/datasets") / item.split("Training Dataset: ")[1]
            elif "Dataset: " in item:
                path = Path("D:/whitehat/llm-datasets") / item.split("Dataset: ")[1]
            elif "Security Tool: " in item:
                path = Path("D:/whitehat/cybersec_repos") / item.split("Security Tool: ")[1]
            elif "Deep Learning: " in item:
                path = Path("D:/whitehat/DeepLearningExamples") / item.split("Deep Learning: ")[1]
            elif "Tutorial: " in item:
                repo_name = item.split("(")[1].strip(")")
                tutorial_name = item.split("Tutorial: ")[1].split(" (")[0]
                path = Path("D:/whitehat/cybersec_repos") / repo_name / "tutorials" / tutorial_name
            elif "Paper: " in item or "Book: " in item:
                repo_name = item.split("(")[1].strip(")")
                file_name = item.split(": ")[1].split(" (")[0]
                content_type = "papers" if "Paper: " in item else "books"
                path = Path("D:/whitehat/cybersec_repos") / repo_name / content_type / f"{file_name}.pdf"
            else:
                return
            
            if path.exists():
                if platform.system() == "Windows":
                    os.startfile(str(path))
                else:
                    subprocess.run(["xdg-open", str(path)])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open material: {str(e)}")
    
    def show_research_papers(self):
        webbrowser.open("https://github.com/jivoi/awesome-ml-for-cybersecurity")
    
    def show_documentation(self):
        if (PROJECT_ROOT / "README.md").exists():
            webbrowser.open(str(PROJECT_ROOT / "README.md"))
        else:
            messagebox.showinfo("Documentation", "Documentation will be available soon.")
    
    def run_awesome_hacking_browser(self):
        """Run the Awesome Hacking Browser."""
        self.status_var.set("[ LAUNCHING BROWSER ]")
        self.root.update()
        
        try:
            # Run the browser script
            subprocess.Popen([sys.executable, str(PROJECT_ROOT / "awesome_hacking_browser.py")])
            
            self.status_var.set("[ BROWSER LAUNCHED ]")
        except Exception as e:
            self.status_var.set(f"[ ERROR ] {str(e)}")
            messagebox.showerror("Error", f"Failed to launch browser: {str(e)}")
    
    def run_ai_code_generator(self):
        """Run the AI Code Generator."""
        self.status_var.set("[ LAUNCHING STARGUARD ]")
        self.root.update()
        
        try:
            # Check if the model exists
            if not MODEL_PATH.exists():
                raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
            
            # Run the test_single_prompt.py script
            if platform.system() == "Windows":
                subprocess.Popen(["start", "cmd", "/k", "python", str(PROJECT_ROOT / "test_single_prompt.py")], shell=True)
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", "python3", str(PROJECT_ROOT / "test_single_prompt.py")])
            
            self.status_var.set("[ AI LAUNCHED ]")
        except Exception as e:
            self.status_var.set(f"[ ERROR ] {str(e)}")
            messagebox.showerror("Error", f"Failed to launch AI: {str(e)}")
    
    def run_cybersec_repos(self):
        """Run the Cybersecurity Repositories browser."""
        self.status_var.set("[ LOADING REPOS ]")
        self.root.update()
        
        try:
            # Check if the repositories exist
            if not CYBERSEC_REPOS_PATH.exists():
                raise FileNotFoundError(f"Repositories not found at {CYBERSEC_REPOS_PATH}")
            
            # Create a Matrix-styled window to browse the repositories
            repos_window = tk.Toplevel(self.root)
            repos_window.title("Cybersecurity Repositories")
            repos_window.geometry("800x600")
            repos_window.configure(bg=ModernTheme.BG_DARK)
            
            # Create a frame for the repositories
            repos_frame = ttk.Frame(repos_window, style="Matrix.TFrame")
            repos_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            # Create a header
            ttk.Label(
                repos_frame,
                text="[ CYBERSECURITY REPOSITORIES ]",
                style="Header.TLabel"
            ).pack(pady=10)
            
            # Create a listbox for the repositories
            repos_listbox = tk.Listbox(
                repos_frame,
                font=("Courier New", 12),
                bg=ModernTheme.BG_MEDIUM,
                fg=ModernTheme.FG_DARK,
                selectmode=tk.SINGLE,
                relief="sunken",
                bd=2
            )
            repos_listbox.pack(fill=tk.BOTH, expand=True, pady=10)
            
            # Add repositories to the listbox
            repos = [d for d in CYBERSEC_REPOS_PATH.iterdir() if d.is_dir()]
            for repo in repos:
                repos_listbox.insert(tk.END, f"[ {repo.name} ]")
            
            # Create a button to open the selected repository
            def open_repo():
                selection = repos_listbox.curselection()
                if selection:
                    repo_name = repos_listbox.get(selection[0]).strip("[ ]")
                    repo_path = CYBERSEC_REPOS_PATH / repo_name
                    
                    # Open the repository in the file explorer
                    if platform.system() == "Windows":
                        os.startfile(repo_path)
                    elif platform.system() == "Darwin":  # macOS
                        subprocess.run(["open", repo_path])
                    else:  # Linux
                        subprocess.run(["xdg-open", repo_path])
            
            ttk.Button(
                repos_frame,
                text="[ OPEN REPOSITORY ]",
                command=open_repo,
                style="Matrix.TButton"
            ).pack(pady=10)
            
            self.status_var.set("[ REPOSITORIES LOADED ]")
        except Exception as e:
            self.status_var.set(f"[ ERROR ] {str(e)}")
            messagebox.showerror("Error", f"Failed to load repositories: {str(e)}")
    
    def run_dataset_manager(self):
        """Run the Dataset Manager."""
        self.status_var.set("[ LAUNCHING MANAGER ]")
        self.root.update()
        
        try:
            # Run the dataset_manager.py script
            if platform.system() == "Windows":
                subprocess.Popen(["start", "cmd", "/k", "python", str(PROJECT_ROOT / "dataset_manager.py"), "list"], shell=True)
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", "python3", str(PROJECT_ROOT / "dataset_manager.py"), "list"])
            
            self.status_var.set("[ MANAGER LAUNCHED ]")
        except Exception as e:
            self.status_var.set(f"[ ERROR ] {str(e)}")
            messagebox.showerror("Error", f"Failed to launch manager: {str(e)}")
    
    def run_ml_cybersec_integration(self):
        """Run the ML Cybersecurity Integration."""
        self.status_var.set("[ LAUNCHING ML TOOLS ]")
        self.root.update()
        
        try:
            # Run the ml_cybersec_integration.py script
            if platform.system() == "Windows":
                subprocess.Popen(["start", "cmd", "/k", "python", str(PROJECT_ROOT / "ml_cybersec_integration.py"), "list-datasets"], shell=True)
            else:
                subprocess.Popen(["x-terminal-emulator", "-e", "python3", str(PROJECT_ROOT / "ml_cybersec_integration.py"), "list-datasets"])
            
            self.status_var.set("[ ML TOOLS LAUNCHED ]")
        except Exception as e:
            self.status_var.set(f"[ ERROR ] {str(e)}")
            messagebox.showerror("Error", f"Failed to launch ML tools: {str(e)}")

    
    
    def switch_model(self, model_name):
        """Switch to a different model"""
        if model_name in self.model_tabs:
            # Import here to modify global
            import sys
            from pathlib import Path
            
            # Update the module's MODEL_PATH
            module = sys.modules[__name__]
            module.MODEL_PATH = Path(self.model_tabs[model_name]["path"])
            
            # Update status
            self.status_var.set(f"[ SWITCHED TO {model_name.upper()} ]")
            
            # Add status message to chat
            chat_history = self.model_tabs[model_name]["chat_history"]
            chat_history.insert(tk.END, f"\n[ SYSTEM ] Switched to {model_name} model\n\n")
            chat_history.see(tk.END)
        else:
            self.status_var.set("[ ERROR: MODEL NOT FOUND ]")

    def show_agents(self):
        """Show the Agents interface"""
        self.clear_content()
        
        # Create agents interface
        agents_frame = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        agents_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = ttk.Label(
            agents_frame,
            text="[ AGENTS ]",
            style="Header.TLabel"
        )
        title.pack(pady=(0, 20))
        
        # Update agent selection
        agent_type_var = tk.StringVar(value="starguard")
        agent_type_menu = ttk.Combobox(
            agents_frame,
            textvariable=agent_type_var,
            values=["starguard", "lora-v2", "malware", "tools", "repos"],
            state="readonly",
            style="Matrix.TCombobox"
        )
        agent_type_menu.pack(pady=10)
        
        # Task input
        task_label = ttk.Label(
            agents_frame,
            text="Enter task:",
            style="Matrix.TLabel"
        )
        task_label.pack(pady=(0, 5))
        
        task_input = tk.Entry(
            agents_frame,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            insertbackground=ModernTheme.FG_DARK,
            font=("Courier New", 10),
            relief="sunken",
            bd=2
        )
        task_input.pack(fill=tk.X, pady=5)
        
        # Run button
        run_btn = ttk.Button(
            agents_frame,
            text="[ RUN AGENT ]",
            command=lambda: self.run_agent(agent_type_var.get(), task_input.get()),
            style="Matrix.TButton"
        )
        run_btn.pack(pady=10)
        
        # Output area
        output = scrolledtext.ScrolledText(
            agents_frame,
            wrap=tk.WORD,
            height=20,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=("Courier New", 10),
            insertbackground=ModernTheme.FG_DARK
        )
        output.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Store output for later use
        self.agents_output = output

    def run_agent(self, agent_type, task):
        """Run the selected agent with the given task"""
        self.agents_output.delete('1.0', tk.END)
        
        try:
            # Create the appropriate agent
            if agent_type == "starguard":
                agent = StarGuardAgent()
            elif agent_type == "lora-v2":
                agent = LoraV2Agent()
            elif agent_type == "malware":
                agent = MalwareAnalysisAgent()
            elif agent_type == "tools":
                agent = SecurityToolsAgent()
            elif agent_type == "repos":
                agent = SecurityReposAgent()
            else:
                raise ValueError("Invalid agent type")
            
            # Run the agent and get response
            response = asyncio.run(agent.run(task))
            
            # Print full response to terminal
            print("\n" + "="*50)
            print(f"Agent: {agent_type}")
            print(f"Task: {task}")
            print("="*50)
            print("\nResponse:")
            print("-"*50)
            print(response)
            print("-"*50 + "\n")
            
            # Show in UI
            self.agents_output.insert(tk.END, response)
            
        except Exception as e:
            error_msg = f"Error running agent: {str(e)}"
            print(error_msg)  # Print to terminal
            self.agents_output.insert(tk.END, error_msg)
    
    def add_show_full_button(self, timestamp, model_name):
        """Add a button to show the full response"""
        chat_history = self.model_tabs[model_name]["chat_history"]
        
        def show_full():
            # Create popup with full response
            popup = tk.Toplevel(self.root)
            popup.title("Full Response")
            popup.geometry("800x600")
            popup.configure(bg=ModernTheme.BG_DARK)
            
            # Add text area with full response
            text_area = scrolledtext.ScrolledText(
                popup,
                wrap=tk.WORD,
                bg=ModernTheme.BG_MEDIUM,
                fg=ModernTheme.FG_DARK,
                font=("Courier New", 10),
                insertbackground=ModernTheme.FG_DARK
            )
            text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Insert full response
            text_area.insert(tk.END, self.full_responses[timestamp])
            text_area.configure(state='disabled')
            
            # Add close button
            close_btn = ttk.Button(
                popup,
                text="[ CLOSE ]",
                command=popup.destroy,
                style="Matrix.TButton"
            )
            close_btn.pack(pady=10)
        
        # Add button to chat history
        button_frame = ttk.Frame(chat_history, style="Matrix.TFrame")
        button_frame.pack(fill=tk.X, pady=5)
        
        show_btn = ttk.Button(
            button_frame,
            text="[ SHOW FULL RESPONSE ]",
            command=show_full,
            style="Matrix.TButton"
        )
        show_btn.pack(side=tk.RIGHT, padx=10)

def main():
    """Main function."""
    root = tk.Tk()
    # Start with matrix rain
    matrix = MatrixRain(root)
    root.mainloop()

if __name__ == "__main__":
    main()  