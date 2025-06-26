# main/gui.py

import os
import sys
import threading
import subprocess
import shlex
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

def get_stahlta_executable():
    this_file = os.path.abspath(__file__)
    level1 = os.path.dirname(this_file)
    level2 = os.path.dirname(level1)
    project_root = os.path.dirname(level2)
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

        self.title("Stahlta Scanner GUI")
        self.geometry("1000x700")
        self.minsize(900, 600)
        self.configure(bg="#2b2b2b")

        # ─── Dark style for ttk ──────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="#e0e0e0", font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#3c3f41", background="#3c3f41", foreground="#ffffff", borderwidth=1)
        style.map("TEntry", fieldbackground=[("focus", "#515355")], background=[("disabled", "#2b2b2b")])
        style.configure("TCombobox", fieldbackground="#3c3f41", background="#3c3f41", foreground="#ffffff")
        style.map("TCombobox", fieldbackground=[("focus", "#515355")], background=[("disabled", "#2b2b2b")])
        style.configure("TButton", background="#3c3f41", foreground="#e0e0e0", borderwidth=1, padding=6)
        style.map("TButton", background=[("active", "#515355"), ("disabled", "#2b2b2b")], foreground=[("disabled", "#7a7a7a")])
        style.configure("TLabelframe", background="#2b2b2b", foreground="#e0e0e0")
        style.configure("TLabelframe.Label", background="#2b2b2b", foreground="#e0e0e0", font=("Segoe UI", 11, "bold"))
        style.configure("Vertical.TScrollbar", gripcount=0, background="#3c3f41", darkcolor="#3c3f41",
                        lightcolor="#3c3f41", troughcolor="#2b2b2b", bordercolor="#2b2b2b", arrowcolor="#e0e0e0")

        # ─── PanedWindow for a 1:2 split ───────────────────────────────
        pw = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        pw.pack(fill="both", expand=True)

        # LEFT pane: inputs (weight=1)
        self.input_frame = ttk.Frame(pw, padding=12)
        pw.add(self.input_frame, weight=1)

        # RIGHT pane: preview + output (weight=2)
        self.right_panel = ttk.Frame(pw)
        pw.add(self.right_panel, weight=2)

        # ─── Build the right panel ─────────────────────────────────────
        self.right_panel.grid_rowconfigure(0, weight=0)  # preview
        self.right_panel.grid_rowconfigure(1, weight=1)  # output
        self.right_panel.grid_columnconfigure(0, weight=1)

        # Command Preview
        self.preview_frame = ttk.LabelFrame(self.right_panel, text="Command Preview", padding=8)
        self.preview_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.command_preview = tk.Text(
            self.preview_frame, height=2, wrap="none",
            state="disabled", background="#1e1e1e", foreground="#dcdcdc",
            insertbackground="#dcdcdc", relief="flat", bd=0
        )
        self.command_preview.pack(fill="x")

        # Scanner Output
        self.output_frame = ttk.LabelFrame(self.right_panel, text="Scanner Output", padding=8)
        self.output_frame.grid(row=1, column=0, sticky="nsew")
        self.output_frame.grid_rowconfigure(0, weight=1)
        self.output_frame.grid_columnconfigure(0, weight=1)
        self.output_text = tk.Text(
            self.output_frame, wrap="none", state="disabled",
            background="#1e1e1e", foreground="#dcdcdc", insertbackground="#dcdcdc",
            relief="flat", bd=0
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(
            self.output_frame, orient="vertical",
            command=self.output_text.yview, style="Vertical.TScrollbar"
        )
        yscroll.grid(row=0, column=1, sticky="ns")
        self.output_text.configure(yscrollcommand=yscroll.set)

        # ─── Build the input widgets ────────────────────────────────────
        self._build_input_widgets()
        self.update_command_preview()

        # ─── On resize, reposition sash at 1/3 width ─────────────────
        self.bind("<Configure>", self._sync_sash)
        
    def _sync_sash(self, event):
        # Keep the sash at ~1/3 of total width
        total = self.winfo_width()
        # first sash index is 0
        try:
            self.nametowidget(self.winfo_children()[0]).sash_place(0, int(total/3), 0)
        except Exception:
            pass

    def _build_input_widgets(self):
        for col in (0, 1, 2, 3, 4):
            self.input_frame.columnconfigure(col, weight=(1 if col in (1, 3) else 0), pad=6)
        r = 0

        # URL
        ttk.Label(self.input_frame, text="URL:*").grid(row=r, column=0, sticky="e", pady=4)
        self.url_var = tk.StringVar()
        e_url = ttk.Entry(self.input_frame, textvariable=self.url_var)
        e_url.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.url_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # Headless
        ttk.Label(self.input_frame, text="Headless:").grid(row=r, column=0, sticky="e", pady=4)
        self.headless_var = tk.StringVar(value="no")
        headless_combo = ttk.Combobox(
            self.input_frame, textvariable=self.headless_var,
            values=["yes", "no"], state="readonly"
        )
        headless_combo.grid(row=r, column=1, sticky="w", pady=4)
        headless_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())
        r += 1

        # Attacks (checkboxes)
        ttk.Label(self.input_frame, text="Attacks:").grid(row=r, column=0, sticky="ne", pady=4)
        self.attack_names = [
            "sqli", "xss", "csrf", "cookie_flags", "headers", "open_redirect", "ssrf"
        ]
        self.attack_vars = {}
        attack_frame = ttk.Frame(self.input_frame)
        attack_frame.grid(row=r, column=1, columnspan=3, sticky="w", pady=4)
        for i, name in enumerate(self.attack_names):
            var = tk.BooleanVar()
            cb = ttk.Checkbutton(
                attack_frame, text=name, variable=var,
                command=self.update_command_preview
            )
            cb.grid(row=0, column=i, sticky="w", padx=(0, 8))
            self.attack_vars[name] = var
        r += 1

        # Scope
        ttk.Label(self.input_frame, text="Scope:").grid(row=r, column=0, sticky="e", pady=4)
        self.scope_var = tk.StringVar(value="domain")
        scope_combo = ttk.Combobox(
            self.input_frame, textvariable=self.scope_var,
            values=["domain", "page", "folder", "subdomain", "parameter"], state="readonly"
        )
        scope_combo.grid(row=r, column=1, sticky="w", pady=4)
        scope_combo.bind("<<ComboboxSelected>>", lambda e: self.update_command_preview())
        r += 1

        # Timeout
        ttk.Label(self.input_frame, text="Timeout:").grid(row=r, column=0, sticky="e", pady=4)
        self.timeout_var = tk.StringVar(value="10")
        e_timeout = ttk.Entry(self.input_frame, textvariable=self.timeout_var, width=8)
        e_timeout.grid(row=r, column=1, sticky="w", pady=4)
        self.timeout_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # Depth
        ttk.Label(self.input_frame, text="Depth:").grid(row=r, column=0, sticky="e", pady=4)
        self.depth_var = tk.StringVar(value="30")
        e_depth = ttk.Entry(self.input_frame, textvariable=self.depth_var, width=8)
        e_depth.grid(row=r, column=1, sticky="w", pady=4)
        self.depth_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # Output Path
        ttk.Label(self.input_frame, text="Output Path:").grid(row=r, column=0, sticky="e", pady=4)
        self.output_var = tk.StringVar(value="reports")
        e_output = ttk.Entry(self.input_frame, textvariable=self.output_var)
        e_output.grid(row=r, column=1, sticky="ew", pady=4)
        self.output_var.trace_add("write", lambda *_: self.update_command_preview())
        b_out = ttk.Button(self.input_frame, text="Browse…", command=self._choose_output_dir)
        b_out.grid(row=r, column=2, sticky="w", padx=(6, 0), pady=4)
        r += 1

        # Wordlist File
        ttk.Label(self.input_frame, text="Wordlist File:").grid(row=r, column=0, sticky="e", pady=4)
        self.wordlist_var = tk.StringVar()
        e_wordlist = ttk.Entry(self.input_frame, textvariable=self.wordlist_var)
        e_wordlist.grid(row=r, column=1, sticky="ew", pady=4)
        self.wordlist_var.trace_add("write", lambda *_: self.update_command_preview())
        b_word = ttk.Button(self.input_frame, text="Browse…", command=self._choose_wordlist_file)
        b_word.grid(row=r, column=2, sticky="w", padx=(6, 0), pady=4)
        r += 1

        # Headers Field
        ttk.Label(self.input_frame, text="Headers:").grid(row=r, column=0, sticky="e", pady=4)
        self.headers_var = tk.StringVar()
        e_headers = ttk.Entry(self.input_frame, textvariable=self.headers_var)
        e_headers.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.headers_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # Cookies Field
        ttk.Label(self.input_frame, text="Cookies:").grid(row=r, column=0, sticky="e", pady=4)
        self.cookies_var = tk.StringVar()
        e_cookies = ttk.Entry(self.input_frame, textvariable=self.cookies_var)
        e_cookies.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.cookies_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # Login URL, Username, Password
        ttk.Label(self.input_frame, text="Login URL:").grid(row=r, column=0, sticky="e", pady=4)
        self.login_url_var = tk.StringVar()
        e_login = ttk.Entry(self.input_frame, textvariable=self.login_url_var)
        e_login.grid(row=r, column=1, columnspan=3, sticky="ew", pady=4)
        self.login_url_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        ttk.Label(self.input_frame, text="Username:").grid(row=r, column=0, sticky="e", pady=4)
        self.username_var = tk.StringVar()
        e_user = ttk.Entry(self.input_frame, textvariable=self.username_var, width=30)
        e_user.grid(row=r, column=1, sticky="w", pady=4)
        self.username_var.trace_add("write", lambda *_: self.update_command_preview())

        ttk.Label(self.input_frame, text="Password:").grid(row=r, column=2, sticky="e", padx=(6, 0), pady=4)
        self.password_var = tk.StringVar()
        e_pass = ttk.Entry(self.input_frame, textvariable=self.password_var, width=30, show="*")
        e_pass.grid(row=r, column=3, sticky="w", pady=4)
        self.password_var.trace_add("write", lambda *_: self.update_command_preview())
        r += 1

        # Run Scanner button
        self.run_button = ttk.Button(
            self.input_frame, text="Run Scanner", command=self._on_run_clicked
        )
        self.run_button.grid(
            row=r, column=0, columnspan=5, pady=(12, 0), ipadx=10, ipady=4
        )
        r += 1
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

        url = self.url_var.get().strip()
        if not url:
            self._set_preview("(fill in URL above)", is_error=True)
            return
        cmd += ["-u", url]

        headless = self.headless_var.get()
        if headless in ("yes", "no"):
            cmd += ["--headless", headless]

        selected = [name for name, var in self.attack_vars.items() if var.get()]
        if selected:
            cmd += ["-a"] + selected

        scope = self.scope_var.get()
        if scope:
            cmd += ["--scope", scope]

        timeout = self.timeout_var.get().strip()
        if timeout:
            cmd += ["-t", timeout]

        depth = self.depth_var.get().strip()
        if depth:
            cmd += ["-d", depth]

        output = self.output_var.get().strip()
        if output:
            cmd += ["-o", output]

        wordlist = self.wordlist_var.get().strip()
        if wordlist:
            cmd += ["-w", wordlist]

        headers = self.headers_var.get().strip()
        if headers:
            cmd += ["--headers", headers]

        cookies = self.cookies_var.get().strip()
        if cookies:
            cmd += ["--cookies", cookies]

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
        self.command_preview.configure(foreground="#ff5555" if is_error else "#dcdcdc")
        self.command_preview.configure(state="disabled")

    def _on_run_clicked(self):
        self.run_button.configure(state="disabled")

        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.configure(state="disabled")

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

        selected = [name for name, var in self.attack_vars.items() if var.get()]
        if selected:
            args += ["-a"] + selected

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

        headers = self.headers_var.get().strip()
        if headers:
            args += ["--headers", headers]

        cookies = self.cookies_var.get().strip()
        if cookies:
            args += ["--cookies", cookies]

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
