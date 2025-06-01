# main/gui.py

import os
import sys
import threading
import subprocess
import platform
import shlex
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

def get_stahlta_executable():
    """
    Return the absolute path to the CLI binary at <project_root>/binaries/stahlta.
    We know this file is at <project_root>/components/main/gui.py,
    so we need to go up three levels to reach <project_root>.
    """
    this_file = os.path.abspath(__file__)                       # e.g. /home/kali/stahlta/components/main/gui.py
    level1 = os.path.dirname(this_file)                          # → /home/kali/stahlta/components/main
    level2 = os.path.dirname(level1)                             # → /home/kali/stahlta/components
    project_root = os.path.dirname(level2)                       # → /home/kali/stahlta
    candidate = os.path.join(project_root, "binaries", "stahlta")

    if not os.path.isfile(candidate):
        messagebox.showerror(
            "Binary Not Found",
            "Could not find the stahlta binary at:\n"
            f"    {candidate}\n\n"
            "Make sure you have binaries/stahlta in your project root."
        )
        sys.exit(1)

    return candidate


class StahltaGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        # ─── Window Configuration ──────────────────────────────────────────
        self.title("Stahlta Scanner GUI")
        self.geometry("900x700")
        self.minsize(800, 600)
        self.configure(bg="#2b2b2b")  # Dark background

        # ─── Apply a custom dark style to ttk widgets ─────────────────────
        style = ttk.Style()
        style.theme_use("clam")  # "clam" is the most configurable built‐in
        style.configure(
            "TFrame",
            background="#2b2b2b"
        )
        style.configure(
            "TLabel",
            background="#2b2b2b",
            foreground="#e0e0e0",
            font=("Segoe UI", 10)
        )
        style.configure(
            "TEntry",
            fieldbackground="#3c3f41",
            background="#3c3f41",
            foreground="#ffffff",
            borderwidth=1
        )
        style.map(
            "TEntry",
            fieldbackground=[("focus", "#515355")],
            background=[("disabled", "#2b2b2b")]
        )
        style.configure(
            "TCombobox",
            fieldbackground="#3c3f41",
            background="#3c3f41",
            foreground="#ffffff"
        )
        style.map(
            "TCombobox",
            fieldbackground=[("focus", "#515355")],
            background=[("disabled", "#2b2b2b")]
        )
        style.configure(
            "TButton",
            background="#3c3f41",
            foreground="#e0e0e0",
            borderwidth=1,
            padding=6
        )
        style.map(
            "TButton",
            background=[("active", "#515355"), ("disabled", "#2b2b2b")],
            foreground=[("disabled", "#7a7a7a")]
        )
        style.configure(
            "TLabelframe",
            background="#2b2b2b",
            foreground="#e0e0e0"
        )
        style.configure(
            "TLabelframe.Label",
            background="#2b2b2b",
            foreground="#e0e0e0",
            font=("Segoe UI", 11, "bold")
        )
        style.configure(
            "Vertical.TScrollbar",
            gripcount=0,
            background="#3c3f41",
            darkcolor="#3c3f41",
            lightcolor="#3c3f41",
            troughcolor="#2b2b2b",
            bordercolor="#2b2b2b",
            arrowcolor="#e0e0e0"
        )

        # ─── Top frame: all input fields ───────────────────────────────
        self.input_frame = ttk.Frame(self, padding=12)
        self.input_frame.grid(
            row=0, column=0, sticky="nsew", padx=12, pady=(12, 6)
        )

        # ─── Command preview (read-only) ──────────────────────────────
        self.preview_frame = ttk.LabelFrame(self, text="Command Preview", padding=8)
        self.preview_frame.grid(
            row=1, column=0, sticky="ew", padx=12, pady=(0, 6)
        )

        # ─── Scanner Output (scrollable) ───────────────────────────────
        self.output_frame = ttk.LabelFrame(self, text="Scanner Output", padding=8)
        self.output_frame.grid(
            row=2, column=0, sticky="nsew", padx=12, pady=(0, 12)
        )

        # Make rows/columns expand properly
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Build input widgets (URL, headless, attacks, etc.)
        self._build_input_widgets()

        # ─── Command Preview Text ───────────────────────────────────────
        self.command_preview = tk.Text(
            self.preview_frame,
            height=2,
            wrap="none",
            state="disabled",
            background="#1e1e1e",
            foreground="#dcdcdc",
            insertbackground="#dcdcdc",
            relief="flat",
            bd=0
        )
        self.command_preview.pack(fill="x")

        # ─── Output Text + Scrollbar ────────────────────────────────────
        self.output_text = tk.Text(
            self.output_frame,
            wrap="none",
            state="disabled",
            background="#1e1e1e",
            foreground="#dcdcdc",
            insertbackground="#dcdcdc",
            relief="flat",
            bd=0
        )
        self.output_text.pack(fill="both", expand=True, side="left")
        yscroll = ttk.Scrollbar(
            self.output_frame,
            orient="vertical",
            command=self.output_text.yview,
            style="Vertical.TScrollbar"
        )
        yscroll.pack(side="right", fill="y")
        self.output_text.configure(yscrollcommand=yscroll.set)

        # Initialize the preview box immediately
        self.update_command_preview()

    def _build_input_widgets(self):
        # We’ll use grid geometry on input_frame with 5 columns:
        #   col 0 = label (right-aligned)
        #   col 1 = entry/combobox (expandable)
        #   col 2 = optional button (“Browse…”)
        #   col 3 = entry/combobox (for multi-part fields like username/password)
        #   col 4 = small hint labels (optional)
        #
        # We set uniform padding and make column 1 and 3 fill available width.

        for col in (0, 1, 2, 3, 4):
            self.input_frame.columnconfigure(col, weight=(1 if col in (1, 3) else 0), pad=6)

        r = 0

        # ─── URL (required) ───────────────────────────────────────────
        ttk.Label(self.input_frame, text="URL:*").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.url_var = tk.StringVar()
        e_url = ttk.Entry(self.input_frame, textvariable=self.url_var)
        e_url.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.url_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Headless (yes/no) ────────────────────────────────────────
        ttk.Label(self.input_frame, text="Headless:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.headless_var = tk.StringVar(value="no")
        headless_combo = ttk.Combobox(
            self.input_frame,
            textvariable=self.headless_var,
            values=["yes", "no"],
            state="readonly"
        )
        headless_combo.grid(row=r, column=1, sticky="w", pady=4)
        headless_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())
        r += 1

        # ─── Attacks (comma- or space-separated) ───────────────────────
        ttk.Label(self.input_frame, text="Attacks:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.attacks_var = tk.StringVar()
        e_attacks = ttk.Entry(self.input_frame, textvariable=self.attacks_var)
        e_attacks.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.attacks_var.trace_add("write", lambda *_: self.update_command_preview())
        ttk.Label(self.input_frame, text="(comma or space)").grid(
            row=r, column=4, sticky="w", pady=4
        )
        r += 1

        # ─── Scope (dropdown) ──────────────────────────────────────────
        ttk.Label(self.input_frame, text="Scope:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.scope_var = tk.StringVar(value="domain")
        scope_combo = ttk.Combobox(
            self.input_frame,
            textvariable=self.scope_var,
            values=["domain", "page", "folder", "subdomain", "parameter"],
            state="readonly"
        )
        scope_combo.grid(row=r, column=1, sticky="w", pady=4)
        scope_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())
        r += 1

        # ─── Timeout (integer) ─────────────────────────────────────────
        ttk.Label(self.input_frame, text="Timeout:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.timeout_var = tk.StringVar(value="10")
        e_timeout = ttk.Entry(self.input_frame, textvariable=self.timeout_var, width=8)
        e_timeout.grid(row=r, column=1, sticky="w", pady=4)
        self.timeout_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Depth (integer) ───────────────────────────────────────────
        ttk.Label(self.input_frame, text="Depth:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.depth_var = tk.StringVar(value="30")
        e_depth = ttk.Entry(self.input_frame, textvariable=self.depth_var, width=8)
        e_depth.grid(row=r, column=1, sticky="w", pady=4)
        self.depth_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Output Path (folder) ─────────────────────────────────────
        ttk.Label(self.input_frame, text="Output Path:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.output_var = tk.StringVar(value="reports")
        e_output = ttk.Entry(self.input_frame, textvariable=self.output_var)
        e_output.grid(row=r, column=1, sticky="ew", pady=4)
        self.output_var.trace_add("write", lambda *_: self.update_command_preview())
        b_out = ttk.Button(self.input_frame, text="Browse…", command=self._choose_output_dir)
        b_out.grid(row=r, column=2, sticky="w", padx=(6, 0), pady=4)
        r += 1

        # ─── Wordlist File Path ────────────────────────────────────────
        ttk.Label(self.input_frame, text="Wordlist File:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.wordlist_var = tk.StringVar()
        e_wordlist = ttk.Entry(self.input_frame, textvariable=self.wordlist_var)
        e_wordlist.grid(row=r, column=1, sticky="ew", pady=4)
        self.wordlist_var.trace_add("write", lambda *_: self.update_command_preview())
        b_word = ttk.Button(self.input_frame, text="Browse…", command=self._choose_wordlist_file)
        b_word.grid(row=r, column=2, sticky="w", padx=(6, 0), pady=4)
        r += 1

        # ─── Login URL, Username, Password ─────────────────────────────
        ttk.Label(self.input_frame, text="Login URL:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.login_url_var = tk.StringVar()
        e_login = ttk.Entry(self.input_frame, textvariable=self.login_url_var)
        e_login.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.login_url_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        ttk.Label(self.input_frame, text="Username:").grid(
            row=r, column=0, sticky="e", pady=4
        )
        self.username_var = tk.StringVar()
        e_user = ttk.Entry(self.input_frame, textvariable=self.username_var, width=30)
        e_user.grid(row=r, column=1, sticky="w", pady=4)
        self.username_var.trace_add("write", lambda *_: self.update_command_preview())

        ttk.Label(self.input_frame, text="Password:").grid(
            row=r, column=2, sticky="e", padx=(6, 0), pady=4
        )
        self.password_var = tk.StringVar()
        e_pass = ttk.Entry(self.input_frame, textvariable=self.password_var, width=30, show="*")
        e_pass.grid(row=r, column=3, sticky="w", pady=4)
        self.password_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # ─── Run Scanner button ────────────────────────────────────────
        self.run_button = ttk.Button(
            self.input_frame,
            text="Run Scanner",
            command=self._on_run_clicked
        )
        self.run_button.grid(
            row=r, column=0, columnspan=5, pady=(12, 0), ipadx=10, ipady=4
        )
        r += 1

        # Add a little spacing at the very bottom
        self.input_frame.rowconfigure(r, weight=1)

    def _choose_output_dir(self):
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.output_var.set(folder)

    def _choose_wordlist_file(self):
        f = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if f:
            self.wordlist_var.set(f)

    def update_command_preview(self):
        exe = get_stahlta_executable()
        cmd = [exe]

        # ─── URL (required)
        url = self.url_var.get().strip()
        if not url:
            self._set_preview("(fill in URL above)", is_error=True)
            return
        cmd += ["-u", url]

        # ─── Headless
        headless = self.headless_var.get()
        if headless in ("yes", "no"):
            cmd += ["--headless", headless]

        # ─── Attacks
        attacks = self.attacks_var.get().strip()
        if attacks:
            raw = attacks.replace(",", " ").split()
            if raw:
                cmd += ["-a"] + raw

        # ─── Scope
        scope = self.scope_var.get()
        if scope:
            cmd += ["--scope", scope]

        # ─── Timeout
        timeout = self.timeout_var.get().strip()
        if timeout:
            cmd += ["-t", timeout]

        # ─── Depth
        depth = self.depth_var.get().strip()
        if depth:
            cmd += ["-d", depth]

        # ─── Output path
        output = self.output_var.get().strip()
        if output:
            cmd += ["-o", output]

        # ─── Wordlist
        wordlist = self.wordlist_var.get().strip()
        if wordlist:
            cmd += ["-w", wordlist]

        # ─── Login URL + credentials
        login_url = self.login_url_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if login_url:
            cmd += ["--login_url", login_url]
            if username:
                cmd += ["--username", username]
            if password:
                cmd += ["--password", password]

        preview_str = " ".join(shlex.quote(part) for part in cmd)
        self._set_preview(preview_str)

    def _set_preview(self, text, is_error=False):
        self.command_preview.configure(state="normal")
        self.command_preview.delete("1.0", tk.END)
        self.command_preview.insert(tk.END, text)

        if is_error:
            self.command_preview.configure(foreground="#ff5555")
        else:
            self.command_preview.configure(foreground="#dcdcdc")

        self.command_preview.configure(state="disabled")

    def _on_run_clicked(self):
        self.run_button.configure(state="disabled")

        # Clear old output
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.configure(state="disabled")

        # Rebuild args the same way as in update_command_preview()
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

        thread = threading.Thread(
            target=self._run_subprocess,
            args=(args,),
            daemon=True
        )
        thread.start()

    def _run_subprocess(self, args_list):
        try:
            proc = subprocess.Popen(
                args_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

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
            self.run_button.configure(state="normal")

    def _append_output(self, text):
        def _task():
            self.output_text.configure(state="normal")
            self.output_text.insert(tk.END, text)
            self.output_text.see(tk.END)
            self.output_text.configure(state="disabled")
        self.output_text.after(0, _task)


if __name__ == "__main__":
    app = StahltaGUI()
    app.mainloop()
