<p align="center">
  <img src="assets/banner.jpg" alt="DumpCert Banner" width="400" style="border-radius: 10px;">
</p>

<h1 align="center">DumpCert</h1>

<p align="center">
  <a href="https://github.com/xDTaraZz"><img src="https://img.shields.io/badge/Developer-xDTaraZ-9333ea.svg?style=flat-square" alt="Developer"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=flat-square" alt="Python"></a>
  <a href="https://microsoft.com/windows"><img src="https://img.shields.io/badge/Platform-Windows-0078D6.svg?style=flat-square" alt="OS"></a>
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License">
</p>

<p align="center">
  <b>PE Digital Certificate & RSA Public Key Extractor</b><br>
  เครื่องมือดึงข้อมูลลายเซ็นดิจิทัล ใบรับรองความปลอดภัย และคีย์สาธารณะแบบดิบ (Raw Modulus & Exponent) จากไฟล์ระบบของ Windows ใช้งานง่าย ปลอดภัย และแม่นยำ
</p>

---

## ⚡ Features
* **Auto-Scan Folder:** ใส่แค่โฟลเดอร์ ค้นหาและคัดเลือกไฟล์เกม/โปรแกรมให้เลือกวิเคราะห์อัตโนมัติ
* **All-in-One Export:** ดึงไฟล์ `.cer` (X.509), `.pem` (Public Key), `.p7b` (PKCS#7) และค่า Modulus/Exponent ดิบบนแรมแบบ Binary สำหรับเขียนโปรแกรมฝั่งไดรเวอร์ได้ทันที
* **Pure Python:** ทำงานรวดเร็ว ไม่จำเป็นต้องติดตั้งไลบรารีภายนอกเพิ่ม
* **Smart UI:** คอนโซลอินเตอร์เฟซสะอาดตา แสดงผลเฉพะาข้อมูลคีย์สำคัญหลักเพื่อการเขียนโค้ดต่อ

---

## 🚀 How to Use

รันสคริปต์หลักเพื่อเริ่มใช้งานหน้าเมนูอินเตอร์เฟซได้ทันที:
```bash
python dumpcert.py
```

---

---

## 💉 InjectCert (Certificate & Signature Injector)
เครื่องมือสำหรับนำใบรับรองดิจิทัล (`.cer`), PKCS#7 (`.p7b`) หรือบล็อกลายเซ็นดิบ (`*_raw_sig.bin`) ยัดเข้าไฟล์ PE (`.exe` / `.dll` / `.sys`) พร้อมอัปเดต Security Directory และ Recalculate PE CheckSum อัตโนมัติ:

```bash
# รันผ่านเมนู Interactive UI
python injectcert.py

# หรือรันผ่านคำสั่ง CLI
python injectcert.py -t dist/VALORANT_Helper.exe -c analyze/VALORANT-Win64-Shipping_cert.cer -o dist/VALORANT_Helper_with_cert.exe
python injectcert.py -t dist/VALORANT_Helper.exe -c analyze/VALORANT-Win64-Shipping_raw_sig.bin -o dist/VALORANT_Helper_signed.exe
```

---

## 📦 Output Files
ไฟล์ผลลัพธ์ที่จะถูกบันทึกไว้ในโฟลเดอร์ปลายทาง:
* **`*_public_key.pem`** — กุญแจสาธารณะ (Public Key) รูปแบบ PEM มาตรฐาน
* **`*_public_key_modulus.bin`** — ค่า Modulus ดิบ (512 ไบต์) สำหรับแมปโครงสร้าง `BCRYPT_RSAKEY_BLOB`
* **`*_public_key_exponent.bin`** — ค่า Exponent ดิบ (3 ไบต์)
* **`*_cert.cer`** — ใบรับรอง X.509 สำหรับตรวจสอบสิทธิ์บน Windows
* **`*_public_key.der`** — โครงสร้างคีย์ดิบแบบไบนารี ASN.1 DER
* **`*_signature.p7b`** — PKCS#7 Certificate Bundle
* **`*_raw_sig.bin`** — บล็อกตารางลายเซ็น PE ต้นฉบับ


