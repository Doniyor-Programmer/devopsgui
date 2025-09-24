# DevOps GUI Toolkit

A lightweight Tkinter desktop application that gathers handy utilities for day-to-day DevOps work. The tool bundles three helpers: a command runner for automation scripts, a basic infrastructure monitor, and a log viewer for quick inspections.

## Features

- **Command Runner** – execute common shell commands (e.g. `kubectl`, `docker`, `terraform`) and review their streaming output without leaving the GUI.
- **Service Monitor** – quickly ping hosts and send HTTP requests to verify reachability of services.
- **Log Viewer** – open arbitrary log files, browse for them, and display their contents inside the application.

## Getting Started

1. Ensure you have Python 3.10 or newer installed. Tkinter ships with the standard CPython distribution on most platforms.
2. Install optional tooling (kubectl, docker, terraform, etc.) for the commands you intend to run.
3. Launch the application:

   ```bash
   python -m devopsgui.app
   ```

   On Windows you may prefer to run `pythonw -m devopsgui.app` to avoid a console window.

## Development Notes

- The application is implemented with only standard-library modules to keep setup simple.
- Executed commands inherit your shell environment. Use caution when running commands that mutate state.
- The project structure is minimal and intentionally dependency-free so that it can be extended to meet custom workflow requirements.

## License

This project is released into the public domain. Modify and adapt as needed for your infrastructure.
