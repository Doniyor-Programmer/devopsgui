"""Simple DevOps desktop companion application."""

from __future__ import annotations

import queue
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.error import URLError
from urllib.request import Request, urlopen


class DevOpsGUI(tk.Tk):
    """Main window that wires together the DevOps helper widgets."""

    def __init__(self) -> None:
        super().__init__()
        self.title("DevOps Control Panel")
        self.geometry("900x600")
        self._create_widgets()

    # ------------------------------------------------------------------
    # widget creation helpers
    def _create_widgets(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        self.command_runner = CommandRunner(notebook)
        notebook.add(self.command_runner, text="Command Runner")

        self.monitor = ServiceMonitor(notebook)
        notebook.add(self.monitor, text="Service Monitor")

        self.logs = LogViewer(notebook)
        notebook.add(self.logs, text="Log Viewer")


# ----------------------------------------------------------------------
# Command Runner
class CommandRunner(ttk.Frame):
    """Panel that allows the user to quickly run shell commands."""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._create_widgets()
        self._command_thread: threading.Thread | None = None
        self._output_queue: queue.Queue[str] = queue.Queue()

    def _create_widgets(self) -> None:
        description = (
            "Run frequently used automation commands and view their output. "
            "Commands are executed through the system shell so use caution."
        )
        ttk.Label(self, text=description, wraplength=850, justify=tk.LEFT).pack(
            anchor=tk.W, padx=10, pady=10
        )

        combo_frame = ttk.Frame(self)
        combo_frame.pack(fill=tk.X, padx=10)

        ttk.Label(combo_frame, text="Preset:").pack(side=tk.LEFT)
        self.command_var = tk.StringVar(value="kubectl get pods --all-namespaces")
        self.command_select = ttk.Combobox(
            combo_frame,
            textvariable=self.command_var,
            values=[
                "kubectl get pods --all-namespaces",
                "docker ps",
                "terraform plan",
                "ansible --version",
                "git status",
            ],
            width=40,
        )
        self.command_select.pack(side=tk.LEFT, padx=5, pady=5)

        ttk.Button(combo_frame, text="Run", command=self._run_command).pack(
            side=tk.LEFT, padx=5
        )

        entry_frame = ttk.Frame(self)
        entry_frame.pack(fill=tk.X, padx=10)
        ttk.Label(entry_frame, text="Custom command:").pack(side=tk.LEFT)
        self.custom_command = tk.StringVar()
        entry = ttk.Entry(entry_frame, textvariable=self.custom_command)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        entry.bind("<Return>", lambda _event: self._run_command())

        self.output = tk.Text(self, height=20)
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar = ttk.Scrollbar(self, command=self.output.yview)
        scrollbar.place(relx=1.0, rely=0.0, relheight=1.0, anchor="ne")
        self.output.configure(yscrollcommand=scrollbar.set)

    def _run_command(self) -> None:
        if self._command_thread and self._command_thread.is_alive():
            messagebox.showinfo("Command Running", "Please wait for the command to finish.")
            return

        command = self.custom_command.get().strip() or self.command_var.get().strip()
        if not command:
            messagebox.showerror("Missing command", "Please provide a command to run.")
            return

        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"$ {command}\n\n")
        self._output_queue = queue.Queue()
        self._command_thread = threading.Thread(
            target=self._execute_command, args=(command,), daemon=True
        )
        self._command_thread.start()
        self.after(100, self._poll_output)

    def _execute_command(self, command: str) -> None:
        with subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        ) as process:
            for line in process.stdout or []:
                self._output_queue.put(line)
            process.wait()
            self._output_queue.put(f"\nProcess exited with code {process.returncode}\n")

    def _poll_output(self) -> None:
        try:
            while True:
                line = self._output_queue.get_nowait()
                self.output.insert(tk.END, line)
                self.output.see(tk.END)
        except queue.Empty:
            pass

        if self._command_thread and self._command_thread.is_alive():
            self.after(100, self._poll_output)


# ----------------------------------------------------------------------
# Service monitor
class ServiceMonitor(ttk.Frame):
    """Utilities for lightweight infrastructure diagnostics."""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._create_widgets()

    def _create_widgets(self) -> None:
        description = (
            "Quickly check connectivity to hosts or web services. "
            "The monitor runs shell commands that may require network access."
        )
        ttk.Label(self, text=description, wraplength=850, justify=tk.LEFT).pack(
            anchor=tk.W, padx=10, pady=10
        )

        # Ping section
        ping_frame = ttk.Labelframe(self, text="Ping Host")
        ping_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(ping_frame, text="Hostname or IP address:").pack(side=tk.LEFT, padx=5)
        self.ping_target = tk.StringVar(value="127.0.0.1")
        ttk.Entry(ping_frame, textvariable=self.ping_target, width=30).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(ping_frame, text="Ping", command=self._run_ping).pack(side=tk.LEFT, padx=5)

        self.ping_output = tk.StringVar()
        ttk.Label(ping_frame, textvariable=self.ping_output).pack(
            side=tk.LEFT, padx=10
        )

        # HTTP section
        http_frame = ttk.Labelframe(self, text="HTTP Health Check")
        http_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(http_frame, text="URL:").pack(side=tk.LEFT, padx=5)
        self.http_url = tk.StringVar(value="https://example.com")
        ttk.Entry(http_frame, textvariable=self.http_url, width=40).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(http_frame, text="Check", command=self._run_http_check).pack(
            side=tk.LEFT, padx=5)

        self.http_output = tk.StringVar()
        ttk.Label(http_frame, textvariable=self.http_output, wraplength=500).pack(
            side=tk.LEFT, padx=10
        )

    def _run_ping(self) -> None:
        target = self.ping_target.get().strip()
        if not target:
            messagebox.showerror("Missing target", "Please provide a host to ping.")
            return

        try:
            result = subprocess.run(
                ["ping", "-c", "1", target],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            self.ping_output.set("Ping utility not available on this system.")
            return
        except subprocess.TimeoutExpired:
            self.ping_output.set("Ping timed out.")
            return

        if result.returncode == 0:
            self.ping_output.set("Reachable")
        else:
            self.ping_output.set("Unreachable")

    def _run_http_check(self) -> None:
        url = self.http_url.get().strip()
        if not url:
            messagebox.showerror("Missing URL", "Please provide a URL to check.")
            return

        try:
            request = Request(url, method="GET")
            with urlopen(request, timeout=10) as response:
                status = response.status
                content_length = response.headers.get("Content-Length", "unknown")
        except URLError as exc:
            self.http_output.set(f"Request failed: {exc}")
            return

        self.http_output.set(f"Status {status}, content length {content_length}")


# ----------------------------------------------------------------------
# Log viewer
class LogViewer(ttk.Frame):
    """Allow the user to inspect log files quickly."""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._create_widgets()

    def _create_widgets(self) -> None:
        description = (
            "Open and inspect log files. Useful for checking agent output or "
            "application logs without leaving the GUI."
        )
        ttk.Label(self, text=description, wraplength=850, justify=tk.LEFT).pack(
            anchor=tk.W, padx=10, pady=10
        )

        control_frame = ttk.Frame(self)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(control_frame, text="Log file path:").pack(side=tk.LEFT, padx=5)
        self.log_path = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.log_path, width=50).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(control_frame, text="Browse", command=self._browse_log).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Load", command=self._load_log).pack(
            side=tk.LEFT, padx=5)

        self.log_output = tk.Text(self, wrap=tk.NONE)
        self.log_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        y_scroll = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.log_output.yview)
        y_scroll.place(relx=1.0, rely=0.0, relheight=1.0, anchor="ne")
        self.log_output.configure(yscrollcommand=y_scroll.set)

        x_scroll = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.log_output.xview)
        x_scroll.pack(fill=tk.X, side=tk.BOTTOM)
        self.log_output.configure(xscrollcommand=x_scroll.set)

    def _browse_log(self) -> None:
        file_path = filedialog.askopenfilename(title="Select log file")
        if file_path:
            self.log_path.set(file_path)

    def _load_log(self) -> None:
        path = Path(self.log_path.get().strip())
        if not path:
            messagebox.showerror("Missing file", "Please provide a log file path.")
            return
        if not path.exists():
            messagebox.showerror("Not found", f"The file {path} does not exist.")
            return
        if not path.is_file():
            messagebox.showerror("Invalid file", f"{path} is not a file.")
            return

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            messagebox.showerror("Error reading file", str(exc))
            return

        self.log_output.delete("1.0", tk.END)
        self.log_output.insert(tk.END, content)
        self.log_output.see("1.0")


# ----------------------------------------------------------------------
def main() -> None:
    app = DevOpsGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
