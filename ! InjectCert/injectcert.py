import os
import sys
import time
import struct
import random
import string
import threading
import ctypes
from ctypes import wintypes
import argparse

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def TitleRandom():
    charset = string.ascii_letters + string.digits
    while True:
        try:
            randTitle = "".join(random.choices(charset, k=12))
            ctypes.windll.kernel32.SetConsoleTitleW(f"InjectCert - {randTitle}")
        except Exception:
            pass
        time.sleep(0.1)

def StartTitleRandom():
    thread = threading.Thread(target=TitleRandom, daemon=True)
    thread.start()

def SetupConsole():
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
            os.system("mode con: cols=88 lines=34")
            kernel32 = ctypes.windll.kernel32
            hOut = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(hOut, ctypes.byref(mode))
            kernel32.SetConsoleMode(hOut, mode.value | 0x0004 | 0x0001)
        except Exception:
            pass
    StartTitleRandom()

def Clear():
    os.system("cls" if os.name == "nt" else "clear")

def SpinLoading(message, duration=0.18):
    frames = ["|", "/", "-", "\\"]
    start = time.time()
    idx = 0
    while time.time() - start < duration:
        print(f"\r  \033[96m[{frames[idx % len(frames)]}]\033[0m \033[97m{message}...\033[0m", end="", flush=True)
        time.sleep(0.03)
        idx += 1
    print(f"\r  \033[92m[+]\033[0m \033[97m{message}\033[0m               ")

def DrawBanner():
    banner = """
\033[1;95m    ___            _           _    ____           _   
   |_ _| _ __     (_)  ___    ___  | |_  / ___|___ _ __ | |_ 
    | | | '_ \\   / /  / _ \\  / __| | __|| |   / _ \\ '__|| __|
    | | | | | | / /  |  __/ | (__  | |_ | |__|  __/ |   | |_ 
   |___||_| |_|/_/    \\___|  \\___|  \\__| \\____\\___|_|    \\__|
\033[0m
\033[90m  --------------------------------------------------------------------------\033[0m
  \033[1;97mInjectCert Engine\033[0m   \033[90m::\033[0m   \033[1;95m(⌐■_■) Dev: xDTaraZ\033[0m   \033[90m::\033[0m   \033[1;92m[INJECTOR READY]\033[0m
\033[90m  --------------------------------------------------------------------------\033[0m"""
    print(banner)

def CalculatePEChecksum(data: bytearray, pe_offset: int) -> int:
    try:
        chk_offset = pe_offset + 0x58
        orig_chk = struct.unpack("<I", data[chk_offset:chk_offset+4])[0]
        data[chk_offset:chk_offset+4] = b"\x00\x00\x00\x00"

        total = 0
        length = len(data)
        for i in range(0, length - (length % 2), 2):
            val = struct.unpack("<H", data[i:i+2])[0]
            total += val
            total = (total & 0xFFFF) + (total >> 16)

        if length % 2 != 0:
            total += data[-1]
            total = (total & 0xFFFF) + (total >> 16)

        total = (total & 0xFFFF) + (total >> 16)
        checksum = (total + length) & 0xFFFFFFFF
        data[chk_offset:chk_offset+4] = struct.pack("<I", orig_chk)
        return checksum
    except Exception:
        return 0

class InjectCert:
    def __init__(self, target_path: str, cert_path: str):
        self.target_path = os.path.abspath(target_path.strip().strip('"'))
        self.cert_path = os.path.abspath(cert_path.strip().strip('"'))
        
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"Target binary not found: {self.target_path}")
        if not os.path.exists(self.cert_path):
            raise FileNotFoundError(f"Certificate file not found: {self.cert_path}")

        with open(self.target_path, "rb") as f:
            self.pe_data = bytearray(f.read())

        with open(self.cert_path, "rb") as f:
            self.cert_data = f.read()

        self.ParsePE()

    def ParsePE(self):
        if len(self.pe_data) < 0x40 or self.pe_data[:2] != b"MZ":
            raise ValueError("Target is not a valid PE binary (MZ header missing).")

        self.pe_offset = struct.unpack("<I", self.pe_data[0x3C:0x40])[0]
        if self.pe_offset + 24 > len(self.pe_data) or self.pe_data[self.pe_offset:self.pe_offset + 4] != b"PE\0\0":
            raise ValueError("Invalid PE signature.")

        opt_offset = self.pe_offset + 24
        self.magic = struct.unpack("<H", self.pe_data[opt_offset:opt_offset + 2])[0]

        if self.magic == 0x10B:
            self.arch = "x86 (32-bit)"
            self.sec_dir_offset = opt_offset + 128
        elif self.magic == 0x20B:
            self.arch = "x64 (64-bit)"
            self.sec_dir_offset = opt_offset + 144
        else:
            raise ValueError(f"Unsupported PE magic: 0x{self.magic:04X}")

        self.sec_rva, self.sec_size = struct.unpack("<II", self.pe_data[self.sec_dir_offset:self.sec_dir_offset + 8])

    def PrepareCertificatePayload(self) -> bytes:
        """
        Processes the input certificate/signature file into a WIN_CERTIFICATE structure.
        """
        # If it is already a raw WIN_CERTIFICATE block (like *_raw_sig.bin)
        if len(self.cert_data) >= 8:
            length, rev, cert_type = struct.unpack("<IHH", self.cert_data[:8])
            # If length matches or is close to cert_data size and revision is 0x0100 or 0x0200
            if (rev in (0x0100, 0x0200) and cert_type in (0x0001, 0x0002) and abs(length - len(self.cert_data)) <= 8):
                return self.cert_data

        ext = os.path.splitext(self.cert_path)[1].lower()
        if ext == ".cer":
            cert_type = 0x0001  # WIN_CERT_TYPE_X509
        elif ext == ".p7b":
            cert_type = 0x0002  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
        else:
            cert_type = 0x0002

        dwLength = 8 + len(self.cert_data)
        wRevision = 0x0200      # WIN_CERT_REVISION_2_0
        header = struct.pack("<IHH", dwLength, wRevision, cert_type)
        payload = header + self.cert_data
        return payload

    def Inject(self, output_path: str = None) -> str:
        if not output_path:
            base, ext = os.path.splitext(self.target_path)
            output_path = f"{base}_signed{ext}"
        else:
            output_path = os.path.abspath(output_path.strip().strip('"'))

        payload = self.PrepareCertificatePayload()

        # Remove existing certificate table if present at end of binary
        clean_pe = bytearray(self.pe_data)
        if self.sec_rva > 0 and self.sec_size > 0:
            if self.sec_rva + self.sec_size >= len(clean_pe) - 16:
                clean_pe = clean_pe[:self.sec_rva]

        # 8-byte alignment for security directory offset
        pad_len = (8 - (len(clean_pe) % 8)) % 8
        clean_pe += b"\x00" * pad_len

        # Pad payload to 8 bytes boundary
        payload_pad = (8 - (len(payload) % 8)) % 8
        padded_payload = payload + (b"\x00" * payload_pad)

        new_sec_offset = len(clean_pe)
        new_sec_size = len(padded_payload)

        # Update PE Security Directory entry
        clean_pe[self.sec_dir_offset:self.sec_dir_offset + 8] = struct.pack("<II", new_sec_offset, new_sec_size)

        # Append signature payload
        final_binary = clean_pe + padded_payload

        # Recalculate checksum
        chk = CalculatePEChecksum(final_binary, self.pe_offset)
        chk_offset = self.pe_offset + 0x58
        final_binary[chk_offset:chk_offset+4] = struct.pack("<I", chk)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(final_binary)

        return output_path

def ScanTargets(search_path="."):
    found = []
    for root, _, files in os.walk(search_path):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in (".exe", ".dll", ".sys") and not name.lower().startswith("api-ms-win-"):
                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                    found.append((path, name, size))
                except Exception:
                    pass
    return found

def Main():
    SetupConsole()
    
    parser = argparse.ArgumentParser(description="InjectCert - Digital Certificate & Signature Injector")
    parser.add_argument("-t", "--target", help="Target PE binary path (.exe, .dll, .sys)")
    parser.add_argument("-c", "--cert", help="Certificate file (.cer, .p7b, *_raw_sig.bin)")
    parser.add_argument("-o", "--output", help="Output path for injected binary")
    args = parser.parse_args()

    if args.target and args.cert:
        try:
            injector = InjectCert(args.target, args.cert)
            out_file = injector.Inject(args.output)
            print(f"\033[92m[+] Successfully injected certificate into: {out_file}\033[0m")
        except Exception as e:
            print(f"\033[91m[-] Injection failed: {e}\033[0m")
        return

    while True:
        Clear()
        DrawBanner()
        print("\n  \033[1;93m[1]\033[0m \033[1;97mSelect Target PE Binary (.exe / .dll)\033[0m")
        print("  \033[1;93m[2]\033[0m \033[1;97mSelect Certificate / Signature (.cer / .p7b / _raw_sig.bin)\033[0m")
        print("  \033[1;93m[3]\033[0m \033[1;97mInject Certificate into Target\033[0m")
        print("  \033[1;93m[0]\033[0m \033[90mExit\033[0m")

        try:
            target_input = input("\n  \033[1;96m[?]\033[0m \033[1;97mTarget PE binary path:\033[0m ").strip().strip('"')
            if not target_input:
                break
            
            cert_input = input("  \033[1;96m[?]\033[0m \033[1;97mCertificate path (e.g. analyze/VALORANT-Win64-Shipping_cert.cer):\033[0m ").strip().strip('"')
            if not cert_input:
                break

            SpinLoading("Analyzing target binary", 0.15)
            injector = InjectCert(target_input, cert_input)
            
            SpinLoading("Injecting certificate table", 0.2)
            SpinLoading("Recalculating PE CheckSum", 0.15)
            out_path = injector.Inject()

            print(f"""
        \033[1;92m/\\_____/\\
       /  o   o  \\   \033[1;97m[+] Certificate Injected Successfully!\033[0m
      ( ==  ^  == )  \033[90m[+] Output: {out_path}\033[0m
       ) xDTaraZ (   \033[90m[+] Target Arch: {injector.arch}\033[0m
      (           )  \033[90m[+] Cert Size: {len(injector.cert_data):,} bytes\033[0m
     ( (  )   (  ) )
    (__(__)___(__)__)\033[0m
""")
        except Exception as ex:
            print(f"\n  \033[91m[-] Error: {ex}\033[0m")

        try:
            input("\n  \033[90mPress Enter to continue...\033[0m")
        except (KeyboardInterrupt, EOFError):
            Clear()
            break

if __name__ == "__main__":
    Main()
