"""Standalone desktop floating alert.

Launched by the dashboard (as a separate process) the moment a threat is detected,
so an on-screen warning appears even when the dashboard is not the focused window.
Shows a borderless, always-on-top red banner with an "Open Dashboard" button that
navigates to the SOC UI so the user can terminate the threat.

Run directly (for testing):
  python alerts/popup.py 92 http://localhost:8501
"""

from __future__ import annotations

import sys
import webbrowser
import tkinter as tk

AUTO_DISMISS_MS = 20000  # popup closes itself after 20s if ignored


def main() -> None:
    pct = sys.argv[1] if len(sys.argv) > 1 else "?"
    url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8501"

    root = tk.Tk()
    root.overrideredirect(True)          # borderless
    root.attributes("-topmost", True)    # always on top of other windows
    try:
        root.attributes("-alpha", 0.97)
    except tk.TclError:
        pass

    w, h = 360, 160
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    x, y = sw - w - 24, sh - h - 70      # bottom-right corner
    root.geometry(f"{w}x{h}+{x}+{y}")
    root.configure(bg="#dc2626")

    tk.Label(root, text="\U0001F6A8  THREAT DETECTED", bg="#dc2626", fg="white",
             font=("Segoe UI", 15, "bold")).pack(pady=(16, 2))
    tk.Label(root, text=f"Suspicious activity — {pct}% severity", bg="#dc2626",
             fg="white", font=("Segoe UI", 10)).pack()

    def open_dashboard() -> None:
        webbrowser.open(url)
        root.destroy()

    btns = tk.Frame(root, bg="#dc2626")
    btns.pack(pady=16)
    tk.Button(btns, text="Open Dashboard", command=open_dashboard,
              bg="white", fg="#dc2626", font=("Segoe UI", 10, "bold"),
              relief="flat", padx=14, pady=6, cursor="hand2").pack(side="left", padx=6)
    tk.Button(btns, text="Dismiss", command=root.destroy,
              bg="#7f1d1d", fg="white", font=("Segoe UI", 10),
              relief="flat", padx=14, pady=6, cursor="hand2").pack(side="left", padx=6)

    root.after(AUTO_DISMISS_MS, root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()
