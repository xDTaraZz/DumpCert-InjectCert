import os
import sys
import time
import struct
import base64
import random
import string
import threading
import ctypes
from ctypes import wintypes

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

class CryptoBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

class AlgorithmId(ctypes.Structure):
    _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", CryptoBlob)]

class BitBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte)), ("cUnusedBits", wintypes.DWORD)]

class PublicKeyInfo(ctypes.Structure):
    _fields_ = [("Algorithm", AlgorithmId), ("PublicKey", BitBlob)]

class CertInfo(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("SerialNumber", CryptoBlob),
        ("SignatureAlgorithm", AlgorithmId),
        ("Issuer", CryptoBlob),
        ("NotBefore", wintypes.FILETIME),
        ("NotAfter", wintypes.FILETIME),
        ("Subject", CryptoBlob),
        ("SubjectPublicKeyInfo", PublicKeyInfo)
    ]

class CertContext(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.POINTER(CertInfo)),
        ("hCertStore", ctypes.c_void_p)
    ]

def TitleRandom():
    charset = string.ascii_letters + string.digits
    while True:
        try:
            randTitle = "".join(random.choices(charset, k=12))
            ctypes.windll.kernel32.SetConsoleTitleW(randTitle)
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

def PlayIntro():
    frames = [
        ("\033[1;96m", "\n       ( •_•)           \033[90m[ STARTING PROGRAM... ]\033[0m\n       <)   )╯\n       /    \\\n"),
        ("\033[1;95m", "\n       ( •_•)>⌐■-■      \033[90m[ LOADING MODULES... ]\033[0m\n       <)   )╯\n       /    \\\n"),
        ("\033[1;93m", "\n       (⌐■_■)           \033[90m[ SETTING PROGRAM... ]\033[0m\n       <)   )╯\n       /    \\\n"),
        ("\033[1;92m", "\n        /\\_____/\\       \033[1;92m[ READY - BY xDTaraZ ]\033[0m\n       /  ^   ^  \\\n      ( ==  o  == )\n       ) xDTaraZ (\n")
    ]
    for color, art in frames:
        Clear()
        print(color + art + "\033[0m")
        time.sleep(0.18)
    time.sleep(0.15)

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
\033[1;96m    ____                                ____           _   
   |  _ \\ _   _ _ __ ___  _ __   ___   / ___|___ _ __ | |_ 
   | | | | | | | '_ ` _ \\| '_ \\ / __| | |   / _ \\ '__|| __|
   | |_| | |_| | | | | | | |_) | (__  | |__|  __/ |   | |_ 
   |____/ \\__,_|_| |_| |_| .__/ \\___|  \\____\\___|_|    \\__|
                         |_|                               \033[0m
\033[90m  --------------------------------------------------------------------------\033[0m
  \033[1;97mDumpCert Engine\033[0m   \033[90m::\033[0m   \033[1;95m(⌐■_■) Dev: xDTaraZ\033[0m   \033[90m::\033[0m   \033[1;92m[READY]\033[0m
\033[90m  --------------------------------------------------------------------------\033[0m"""
    print(banner)

def ScanBinaries(targetPath):
    if os.path.isfile(targetPath):
        return [(targetPath, os.path.basename(targetPath), os.path.getsize(targetPath))]
    
    found = []
    for root, _, files in os.walk(targetPath):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext not in (".exe", ".sys", ".dll") or name.lower().startswith("api-ms-win-"):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as stream:
                    hdr = stream.read(1024)
                if len(hdr) < 0x40 or hdr[:2] != b"MZ":
                    continue
                peOff = struct.unpack("<I", hdr[0x3C:0x40])[0]
                with open(path, "rb") as stream:
                    stream.seek(peOff)
                    peHdr = stream.read(256)
                if peHdr[:4] != b"PE\0\0":
                    continue
                magic = struct.unpack("<H", peHdr[24:26])[0]
                secOff = peOff + (144 if magic == 0x20B else 128) + 24
                with open(path, "rb") as stream:
                    stream.seek(secOff)
                    rva, size = struct.unpack("<II", stream.read(8))
                if size > 0 and rva > 0:
                    prio = 1 if ext == ".exe" else (2 if ext == ".sys" else 3)
                    found.append((prio, path, name, os.path.getsize(path)))
            except Exception:
                continue

    found.sort(key=lambda x: (x[0], -x[3]))
    return [(item[1], item[2], item[3]) for item in found]

def SelectTarget(inputPath):
    cleanPath = os.path.abspath(inputPath.strip().strip('"'))
    if not os.path.exists(cleanPath):
        raise FileNotFoundError(f"Path does not exist: {cleanPath}")

    if os.path.isfile(cleanPath):
        return cleanPath

    items = ScanBinaries(cleanPath)
    if not items:
        raise ValueError(f"No valid targets found in: {cleanPath}")

    if len(items) == 1:
        print(f"\n  \033[92m[+]\033[0m Target: \033[1;97m{items[0][0]}\033[0m")
        return items[0][0]

    print(f"\n  \033[93m[i] Found {len(items)} matching binaries:\033[0m")
    limit = min(len(items), 10)
    for idx in range(limit):
        p, n, s = items[idx]
        print(f"    \033[96m[{idx + 1:02d}]\033[0m \033[1;97m{n:30}\033[0m \033[90m({s:,} bytes)\033[0m")

    try:
        sel = input(f"\n  Select index (1-{limit}) [Default: 1]: ").strip()
    except (KeyboardInterrupt, EOFError):
        return items[0][0]
    if not sel:
        return items[0][0]
    try:
        choice = int(sel) - 1
        if 0 <= choice < limit:
            return items[choice][0]
    except Exception:
        pass
    return items[0][0]

class DumpCert:
    def __init__(self, targetPath):
        self.path = SelectTarget(targetPath)
        with open(self.path, "rb") as stream:
            self.data = bytearray(stream.read())
        self.ParsePE()

    def ParsePE(self):
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise ValueError("Target validation failed.")
        
        self.peOff = struct.unpack("<I", self.data[0x3C:0x40])[0]
        if self.peOff + 24 > len(self.data) or self.data[self.peOff:self.peOff + 4] != b"PE\0\0":
            raise ValueError("Invalid target format.")
        
        optOff = self.peOff + 24
        self.magic = struct.unpack("<H", self.data[optOff:optOff + 2])[0]
        
        if self.magic == 0x10B:
            self.arch = "x86 (32-bit)"
            self.secDirOff = optOff + 128
        elif self.magic == 0x20B:
            self.arch = "x64 (64-bit)"
            self.secDirOff = optOff + 144
        else:
            raise ValueError("Unsupported format.")
        
        self.secRva, self.secSize = struct.unpack("<II", self.data[self.secDirOff:self.secDirOff + 8])

    @property
    def IsSigned(self):
        return self.secSize > 0 and self.secRva > 0

    def ExtractRaw(self):
        if not self.IsSigned:
            raise ValueError("Target has no signature payload.")
        return bytes(self.data[self.secRva:self.secRva + self.secSize])

    def ExtractP7B(self):
        raw = self.ExtractRaw()
        tableSize = struct.unpack("<I", raw[:4])[0]
        return raw[8:min(tableSize, len(raw))]

    def ExtractCryptoObjects(self):
        if not self.IsSigned or sys.platform != "win32":
            return None, []

        try:
            crypt32 = ctypes.windll.crypt32
            hStore = ctypes.c_void_p()
            queryOk = crypt32.CryptQueryObject(
                1, ctypes.c_wchar_p(self.path), 0x00003FFE, 0x0000000E, 0,
                None, None, None, ctypes.byref(hStore), None, None
            )

            if not queryOk or not hStore.value:
                return None, []

            crypt32.CertEnumCertificatesInStore.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            crypt32.CertEnumCertificatesInStore.restype = ctypes.POINTER(CertContext)

            certs = []
            publicKeyInfo = None
            ctx = crypt32.CertEnumCertificatesInStore(hStore, None)

            while ctx:
                rawCert = bytes((ctypes.c_ubyte * ctx.contents.cbCertEncoded).from_address(ctypes.addressof(ctx.contents.pbCertEncoded.contents)))
                certs.append(rawCert)

                if not publicKeyInfo:
                    pkInfo = ctx.contents.pCertInfo.contents.SubjectPublicKeyInfo
                    oid = pkInfo.Algorithm.pszObjId.decode("utf-8") if pkInfo.Algorithm.pszObjId else "1.2.840.113549.1.1.1"
                    pubBytes = bytes((ctypes.c_ubyte * pkInfo.PublicKey.cbData).from_address(ctypes.addressof(pkInfo.PublicKey.pbData.contents)))
                    
                    alg = "RSA" if "1.2.840.113549.1.1" in oid else ("ECC" if "1.2.840.10045" in oid else "Standard")
                    b64Key = base64.b64encode(pubBytes).decode("ascii")
                    
                    pem = "-----BEGIN PUBLIC KEY-----\n"
                    for i in range(0, len(b64Key), 64):
                        pem += b64Key[i:i + 64] + "\n"
                    pem += "-----END PUBLIC KEY-----\n"

                    modBytes, expBytes, expVal = self.ParseRSAParams(pubBytes)

                    publicKeyInfo = {
                        "alg": alg,
                        "bits": len(modBytes) * 8 if modBytes else len(pubBytes) * 8,
                        "pem": pem,
                        "raw": pubBytes,
                        "modulus": modBytes,
                        "exponent": expBytes,
                        "expVal": expVal
                    }

                ctx = crypt32.CertEnumCertificatesInStore(hStore, ctx)

            crypt32.CertCloseStore(hStore, 0)
            return publicKeyInfo, certs
        except Exception:
            return None, []

    def ParseRSAParams(self, keyBytes):
        try:
            if keyBytes[0] != 0x30:
                return None, None, 0
            
            offset = 1
            if keyBytes[offset] >= 0x80:
                offset += 1 + (keyBytes[offset] & 0x7F)
            else:
                offset += 1

            if keyBytes[offset] != 0x02:
                return None, None, 0
            offset += 1

            if keyBytes[offset] >= 0x80:
                nBytes = keyBytes[offset] & 0x7F
                modLen = 0
                for i in range(nBytes):
                    modLen = (modLen << 8) | keyBytes[offset + 1 + i]
                offset += 1 + nBytes
            else:
                modLen = keyBytes[offset]
                offset += 1

            mod = keyBytes[offset:offset + modLen]
            if mod[0] == 0:
                mod = mod[1:]
            offset += modLen

            if keyBytes[offset] != 0x02:
                return mod, None, 0
            offset += 1

            expLen = keyBytes[offset]
            offset += 1
            exp = keyBytes[offset:offset + expLen]
            expVal = int.from_bytes(exp, "big")

            return mod, exp, expVal
        except Exception:
            return None, None, 0

    def DumpAll(self, outDir="analyze"):
        destDir = os.path.abspath(outDir.strip().strip('"'))
        os.makedirs(destDir, exist_ok=True)
        base = os.path.splitext(os.path.basename(self.path))[0]
        
        pk, certs = self.ExtractCryptoObjects()
        results = []

        cerPath = os.path.join(destDir, f"{base}_cert.cer")
        cerData = certs[0] if certs else self.ExtractP7B()
        with open(cerPath, "wb") as f:
            f.write(cerData)
        results.append((cerPath, len(cerData), "Certificate"))

        if pk:
            pemPath = os.path.join(destDir, f"{base}_public_key.pem")
            with open(pemPath, "w", encoding="utf-8") as f:
                f.write(pk["pem"])
            results.append((pemPath, len(pk["pem"]), "Public Key"))

            derPath = os.path.join(destDir, f"{base}_public_key.der")
            with open(derPath, "wb") as f:
                f.write(pk["raw"])
            results.append((derPath, len(pk["raw"]), "Key Binary"))

            if pk["modulus"]:
                modPath = os.path.join(destDir, f"{base}_public_key_modulus.bin")
                with open(modPath, "wb") as f:
                    f.write(pk["modulus"])
                results.append((modPath, len(pk["modulus"]), "Raw Modulus"))

            if pk["exponent"]:
                expPath = os.path.join(destDir, f"{base}_public_key_exponent.bin")
                with open(expPath, "wb") as f:
                    f.write(pk["exponent"])
                results.append((expPath, len(pk["exponent"]), "Raw Exponent"))

        p7bPath = os.path.join(destDir, f"{base}_signature.p7b")
        p7bData = self.ExtractP7B()
        with open(p7bPath, "wb") as f:
            f.write(p7bData)
        results.append((p7bPath, len(p7bData), "Package"))

        rawPath = os.path.join(destDir, f"{base}_raw_sig.bin")
        rawData = self.ExtractRaw()
        with open(rawPath, "wb") as f:
            f.write(rawData)
        results.append((rawPath, len(rawData), "Signature"))

        return results

    def GetDetails(self):
        pk, _ = self.ExtractCryptoObjects()
        return {
            "name": os.path.basename(self.path),
            "path": self.path,
            "arch": self.arch,
            "size": len(self.data),
            "signed": self.IsSigned,
            "pk": pk
        }

def Code():
    SetupConsole()
    PlayIntro()
    while True:
        Clear()
        DrawBanner()

        try:
            userInput = input("\n  \033[1;96m[?]\033[0m \033[1;97mInput game folder path:\033[0m ").strip().strip('"')
        except (KeyboardInterrupt, EOFError):
            Clear()
            break

        if not userInput:
            Clear()
            break

        try:
            instance = DumpCert(userInput)
            
            SpinLoading("Processing target", 0.15)
            SpinLoading("Analyzing signature", 0.12)
            info = instance.GetDetails()

            print("\n  \033[90m-- \033[1;97mTARGET DETAILS\033[0m \033[90m--------------------------------------------------------\033[0m")
            print(f"  \033[96m+\033[0m File:         \033[1;97m{info['name']}\033[0m")
            print(f"  \033[96m+\033[0m Architecture: \033[92m{info['arch']}\033[0m")
            print(f"  \033[96m+\033[0m Size:         \033[97m{info['size']:,} bytes\033[0m")
            print(f"  \033[96m+\033[0m Status:       \033[92m{'Valid Signature' if info['signed'] else 'Unsigned'}\033[0m")
            
            if info["signed"] and info["pk"]:
                pk = info["pk"]
                print(f"  \033[96m+\033[0m Key Type:     \033[1;92m{pk['alg']}\033[0m  \033[90m({pk['bits']}-bit)\033[0m")
                if pk["expVal"]:
                    print(f"  \033[96m+\033[0m Exponent:     \033[97m{pk['expVal']}\033[0m \033[90m(0x{pk['expVal']:X})\033[0m")
                if pk["modulus"]:
                    print(f"  \033[96m+\033[0m Modulus:\n    \033[90m{pk['modulus'].hex().upper()[:64]}...\033[0m")

            print("\n  \033[90m-- \033[1;97mEXPORTING ASSETS\033[0m \033[90m----------------------------------------------------\033[0m")
            SpinLoading("Extracting package", 0.15)
            SpinLoading("Saving output files", 0.12)
            
            results = instance.DumpAll("analyze")
            print(f"""
        \033[1;92m/\\_____/\\
       /  o   o  \\   \033[1;97m[+] Extraction Completed Successfully!\033[0m
      ( ==  ^  == )  \033[90m[+] Total: {len(results)} files exported -> {os.path.abspath('analyze')}\033[0m
       ) xDTaraZ (
      (           )
     ( (  )   (  ) )
    (__(__)___(__)__)\033[0m
""")
            for p, s, d in results:
                print(f"    \033[96m+\033[0m \033[1;97m{os.path.basename(p):34}\033[0m \033[92m{s:>9,} B\033[0m  \033[90m[{d}]\033[0m")

        except Exception as ex:
            print(f"\n  \033[91m[-] Error: {ex}\033[0m")
        
        try:
            input("\n  \033[90mPress Enter to continue...\033[0m")
        except (KeyboardInterrupt, EOFError):
            Clear()
            break

def Main():
    try:
        Code()
    except (KeyboardInterrupt, EOFError):
        Clear()
        sys.exit(0)

if __name__ == "__main__":
    Main()