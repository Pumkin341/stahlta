# main/gui.py

import os
import sys
import threading
import subprocess
import platform
import shlex
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ─────────────────────────────────────────────────────────────────────
# Helper: locate the 'stahlta' binary under <project_root>/binaries/stahlta
# ─────────────────────────────────────────────────────────────────────
def get_stahlta_executable():
    """
    Return the absolute path to the CLI binary at <project_root>/binaries/stahlta.
    We assume this file lives at: <project_root>/main/gui.py,
    so two levels up is <project_root>.
    """
    # 1) Get the absolute path to <project_root>/main/gui.py
    this_file = os.path.abspath(__file__)
    main_folder = os.path.dirname(this_file)            # .../project_root/main
    project_root = os.path.dirname(main_folder)         # .../project_root

    # 2) Candidate path for the Linux binary:
    candidate = os.path.join(project_root, "binaries", "stahlta")

    # 3) If on Windows, you might have a .exe, but as per your instructions
    #    we only care about leaving the Linux binary alone. (Adjust if you add a Windows version.)
    if not os.path.isfile(candidate):
        messagebox.showerror(
            "Binary Not Found",
            "Could not find the stahlta binary at:\n"
            f"{candidate}\n\n"
            "Make sure you have binaries/stahlta in your project root."
        )
        sys.exit(1)

    return candidate

# ─────────────────────────────────────────────────────────────────────
# Main Tkinter window
# ─────────────────────────────────────────────────────────────────────
class StahltaGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Stahlta Scanner GUI")
        self.geometry("900x700")
        self.resizable(True, True)

        # ─── Top frame: all input fields ───────────────────────────────
        self.input_frame = ttk.Frame(self, padding=10)
        self.input_frame.pack(fill="x", side="top")

        # ─── Command preview (read-only) ──────────────────────────────
        self.preview_frame = ttk.LabelFrame(self, text="Command Preview", padding=10)
        self.preview_frame.pack(fill="x", padx=10, pady=(0, 10))

        # ─── Scanner Output (scrollable) ───────────────────────────────
        self.output_frame = ttk.LabelFrame(self, text="Scanner Output", padding=10)
        self.output_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Build input widgets (URL, headless, attacks, etc.)
        self._build_input_widgets()

        # A) Text widget to display the exact command that will be run
        self.command_preview = tk.Text(
            self.preview_frame,
            height=2,
            wrap="none",
            state="disabled",
            background="#f0f0f0"
        )
        self.command_preview.pack(fill="x")

        # B) Text widget + Scrollbar for stdout/stderr
        self.output_text = tk.Text(
            self.output_frame,
            wrap="none",
            state="disabled"
        )
        self.output_text.pack(fill="both", expand=True, side="left")
        yscroll = ttk.Scrollbar(
            self.output_frame,
            orient="vertical",
            command=self.output_text.yview
        )
        yscroll.pack(side="right", fill="y")
        self.output_text.configure(yscrollcommand=yscroll.set)

        # Initialize the preview box immediately
        self.update_command_preview()

    # ─────────────────────────────────────────────────────────────────
    # Build each input field (URL, headless, attacks, scope, timeout, depth,
    # output folder, wordlist, login credentials, Run button)
    # ─────────────────────────────────────────────────────────────────
    def _build_input_widgets(self):
        r = 0

        # ─── URL (required) ────────────────────────────────────────
        ttk.Label(self.input_frame, text="URL:*").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.url_var = tk.StringVar()
        e_url = ttk.Entry(self.input_frame, textvariable=self.url_var, width=50)
        e_url.grid(row=r, column=1, columnspan=3, sticky="w", pady=2)
        self.url_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Headless (yes/no) ────────────────────────────────────
        ttk.Label(self.input_frame, text="Headless:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.headless_var = tk.StringVar(value="no")
        headless_combo = ttk.Combobox(
            self.input_frame,
            textvariable=self.headless_var,
            values=["yes", "no"],
            state="readonly",
            width=8
        )
        headless_combo.grid(row=r, column=1, sticky="w", pady=2)
        headless_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())
        r += 1

        # ─── Attacks (comma- or space-separated) ────────────────────
        ttk.Label(self.input_frame, text="Attacks:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.attacks_var = tk.StringVar()
        e_attacks = ttk.Entry(self.input_frame, textvariable=self.attacks_var, width=50)
        e_attacks.grid(row=r, column=1, columnspan=3, sticky="w", pady=2)
        self.attacks_var.trace_add("write", lambda *_: self.update_command_preview())
        ttk.Label(self.input_frame, text="(comma- or space-separated)").grid(
            row=r, column=4, sticky="w", padx=(5, 0)
        )
        r += 1

        # ─── Scope (dropdown) ───────────────────────────────────────
        ttk.Label(self.input_frame, text="Scope:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.scope_var = tk.StringVar(value="domain")
        scope_combo = ttk.Combobox(
            self.input_frame,
            textvariable=self.scope_var,
            values=["domain", "page", "folder", "subdomain", "parameter"],
            state="readonly",
            width=12
        )
        scope_combo.grid(row=r, column=1, sticky="w", pady=2)
        scope_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())
        r += 1

        # ─── Timeout (integer) ───────────────────────────────────────
        ttk.Label(self.input_frame, text="Timeout:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.timeout_var = tk.StringVar(value="10")
        e_timeout = ttk.Entry(self.input_frame, textvariable=self.timeout_var, width=8)
        e_timeout.grid(row=r, column=1, sticky="w", pady=2)
        self.timeout_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Depth (integer) ────────────────────────────────────────
        ttk.Label(self.input_frame, text="Depth:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.depth_var = tk.StringVar(value="30")
        e_depth = ttk.Entry(self.input_frame, textvariable=self.depth_var, width=8)
        e_depth.grid(row=r, column=1, sticky="w", pady=2)
        self.depth_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Output Path (folder) ────────────────────────────────────
        ttk.Label(self.input_frame, text="Output Path:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.output_var = tk.StringVar(value="reports")
        e_output = ttk.Entry(self.input_frame, textvariable=self.output_var, width=40)
        e_output.grid(row=r, column=1, sticky="w", pady=2)
        self.output_var.trace_add("write", lambda *_: self.update_command_preview())
        b_out = ttk.Button(self.input_frame, text="Browse…", command=self._choose_output_dir)
        b_out.grid(row=r, column=2, sticky="w", padx=(5, 0))
        r += 1

        # ─── Wordlist File Path ──────────────────────────────────────
        ttk.Label(self.input_frame, text="Wordlist File:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.wordlist_var = tk.StringVar()
        e_wordlist = ttk.Entry(self.input_frame, textvariable=self.wordlist_var, width=40)
        e_wordlist.grid(row=r, column=1, sticky="w", pady=2)
        self.wordlist_var.trace_add("write", lambda *_: self.update_command_preview())
        b_word = ttk.Button(self.input_frame, text="Browse…", command=self._choose_wordlist_file)
        b_word.grid(row=r, column=2, sticky="w", padx=(5, 0))
        r += 1

        # ─── Login URL, Username, Password ───────────────────────────
        ttk.Label(self.input_frame, text="Login URL:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.login_url_var = tk.StringVar()
        e_login = ttk.Entry(self.input_frame, textvariable=self.login_url_var, width=40)
        e_login.grid(row=r, column=1, columnspan=3, sticky="w", pady=2)
        self.login_url_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        ttk.Label(self.input_frame, text="Username:").grid(
            row=r, column=0, sticky="e", padx=(0, 5), pady=2
        )
        self.username_var = tk.StringVar()
        e_user = ttk.Entry(self.input_frame, textvariable=self.username_var, width=30)
        e_user.grid(row=r, column=1, sticky="w", pady=2)
        self.username_var.trace_add("write", lambda *_: self.update_command_preview())

        ttk.Label(self.input_frame, text="Password:").grid(
            row=r, column=2, sticky="e", padx=(5, 5), pady=2
        )
        self.password_var = tk.StringVar()
        e_pass = ttk.Entry(self.input_frame, textvariable=self.password_var, width=30, show="*")
        e_pass.grid(row=r, column=3, sticky="w", pady=2)
        self.password_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Run Scanner button ───────────────────────────────────────
        self.run_button = ttk.Button(
            self.input_frame,
            text="Run Scanner",
            command=self._on_run_clicked
        )
        self.run_button.grid(row=r, column=0, columnspan=5, pady=(10, 0))
        r += 1

        # Add padding to all columns/rows
        for col in range(5):
            self.input_frame.columnconfigure(col, pad=5)
        for row_idx in range(r):
            self.input_frame.rowconfigure(row_idx, pad=2)

    # ─────────────────────────────────────────────────────────────────
    # Browse for an output directory
    # ─────────────────────────────────────────────────────────────────
    def _choose_output_dir(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_var.set(folder)

    # ─────────────────────────────────────────────────────────────────
    # Browse for a wordlist file
    # ─────────────────────────────────────────────────────────────────
    def _choose_wordlist_file(self):
        f = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if f:
            self.wordlist_var.set(f)

    # ─────────────────────────────────────────────────────────────────
    # Rebuild the full command line and place it in the preview box
    # ─────────────────────────────────────────────────────────────────
    def update_command_preview(self):
        exe = get_stahlta_executable()
        cmd = [exe]

        # URL (required)
        url = self.url_var.get().strip()
        if not url:
            self._set_preview("(fill in URL above)")
            return
        cmd += ["-u", url]

        # Headless
        headless = self.headless_var.get()
        if headless in ("yes", "no"):
            cmd += ["--headless", headless]

        # Attacks
        attacks = self.attacks_var.get().strip()
        if attacks:
            raw = attacks.replace(",", " ").split()
            if raw:
                cmd += ["-a"] + raw

        # Scope
        scope = self.scope_var.get()
        if scope:
            cmd += ["--scope", scope]

        # Timeout
        timeout = self.timeout_var.get().strip()
        if timeout:
            cmd += ["-t", timeout]

        # Depth
        depth = self.depth_var.get().strip()
        if depth:
            cmd += ["-d", depth]

        # Output path
        output = self.output_var.get().strip()
        if output:
            cmd += ["-o", output]

        # Wordlist
        wordlist = self.wordlist_var.get().strip()
        if wordlist:
            cmd += ["-w", wordlist]

        # Login URL + credentials
        login_url = self.login_url_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if login_url:
            cmd += ["--login_url", login_url]
            if username:
                cmd += ["--username", username]
            if password:
                cmd += ["--password", password]

        # Build one shell-quoted string for display
        preview_str = " ".join(shlex.quote(part) for part in cmd)
        self._set_preview(preview_str)

    def _set_preview(self, text):
        self.command_preview.configure(state="normal")
        self.command_preview.delete("1.0", tk.END)
        self.command_preview.insert(tk.END, text)
        self.command_preview.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────────
    # “Run Scanner” button callback: spawn subprocess in a thread
    # ─────────────────────────────────────────────────────────────────
    def _on_run_clicked(self):
        # Disable the Run button while scanning
        self.run_button.configure(state="disabled")

        # Clear old output
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.configure(state="disabled")

        # Rebuild the args exactly as in update_command_preview()
        exe = get_stahlta_executable()
        args = [exe]

        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "URL is required.")
            self.run_button.configure(state="normal")
            return
        args += ["-u", url]

        headless = self.headless_var.get()
        if headless in ("yes", "no"):
            args += ["--headless", headless]

        attacks = self.attacks_var.get().strip()
        if attacks:
            raw = attacks.replace(",", " ").split()
            args += ["-a"] + raw

        scope = self.scope_var.get()
        if scope:
            args += ["--scope", scope]

        timeout = self.timeout_var.get().strip()
        if timeout:
            args += ["-t", timeout]

        depth = self.depth_var.get().strip()
        if depth:
            args += ["-d", depth]

        output = self.output_var.get().strip()
        if output:
            args += ["-o", output]

        wordlist = self.wordlist_var.get().strip()
        if wordlist:
            args += ["-w", wordlist]

        login_url = self.login_url_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if login_url:
            args += ["--login_url", login_url]
            if username:
                args += ["--username", username]
            if password:
                args += ["--password", password]

        # Launch subprocess in a background thread so the GUI stays responsive
        thread = threading.Thread(
            target=self._run_subprocess,
            args=(args,),
            daemon=True
        )
        thread.start()

    # ─────────────────────────────────────────────────────────────────
    # Background work: run subprocess, capture stdout/stderr, append to Text
    # ─────────────────────────────────────────────────────────────────
    def _run_subprocess(self, args_list):
        try:
            proc = subprocess.Popen(
                args_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Helper to read one pipe and write into the Text widget
            def reader(pipe):
                for line in iter(pipe.readline, ""):
                    self._append_output(line)
                pipe.close()

            t_out = threading.Thread(target=reader, args=(proc.stdout,), daemon=True)
            t_err = threading.Thread(target=reader, args=(proc.stderr,), daemon=True)
            t_out.start()
            t_err.start()

            proc.wait()
            t_out.join()
            t_err.join()
            exit_code = proc.returncode
            self._append_output(f"\n[Process exited with code {exit_code}]\n")
        except Exception as e:
            self._append_output(f"\n[Error launching process: {e}]\n")
        finally:
            # Re-enable the Run button
            self.run_button.configure(state="normal")

    # ─────────────────────────────────────────────────────────────────
    # Insert text into the output Text widget in a thread-safe way
    # ─────────────────────────────────────────────────────────────────
    def _append_output(self, text):
        def _task():
            self.output_text.configure(state="normal")
            self.output_text.insert(tk.END, text)
            self.output_text.see(tk.END)
            self.output_text.configure(state="disabled")
        self.output_text.after(0, _task)
