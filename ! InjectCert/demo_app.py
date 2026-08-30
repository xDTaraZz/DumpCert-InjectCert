import os
import sys
import time
import ctypes

def setup_console():
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
            ctypes.windll.kernel32.SetConsoleTitleW("VALORANT Client Security Helper")
        except Exception:
            pass

def main():
    setup_console()
    print("\033[1;96m" + "=" * 60 + "\033[0m")
    print("\033[1;92m   [+] VALORANT Client Security & Launcher Demo App\033[0m")
    print("\033[90m   Digital Certificate Embedded Program\033[0m")
    print("\033[1;96m" + "=" * 60 + "\033[0m\n")
    
    print("  \033[93m[*] Program Status:\033[0m \033[92mRunning\033[0m")
    print("  \033[93m[*] Target Architecture:\033[0m \033[97mx64 (Windows)\033[0m")
    print("  \033[93m[*] Certificate Profile:\033[0m \033[96mVALORANT-Win64-Shipping (Riot Games, Inc.)\033[0m")
    
    print("\n  \033[90mPress Enter to exit...\033[0m")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass

if __name__ == "__main__":
    main()
