import os
import tkinter as tk

from launcher import ChimeraLauncher


def main() -> None:
    os.environ["CHIMERA_MATRIX"] = "0"
    root = tk.Tk()
    ChimeraLauncher(root)
    root.after(200, root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()
