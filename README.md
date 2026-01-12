# IMAP DKIM/DMARC Email Reader

เครื่องมือสำหรับอ่านอีเมลจาก IMAP server ตรวจสอบลายเซ็น DKIM/DMARC และจัดการอีเมล

## คุณสมบัติ

- ✓ อ่านอีเมลจาก IMAP server
- ✓ ตรวจสอบลายเซ็น DKIM ของอีเมล
- ✓ ตรวจสอบ DMARC (Domain-based Message Authentication, Reporting & Conformance)
- ✓ ย้ายอีเมลที่มี DMARC ไปยังโฟลเดอร์ dmarc-report อัตโนมัติ
- ✓ แสดงรายการอีเมลในโฟลเดอร์ dmarc-report
- ✓ Scan อีเมลตามช่วงวันที่ (เช่น scan เฉพาะ 7 วันล่าสุด)
- ✓ ดึง attachments จากอีเมลและบันทึกแยกตามวัน
- ✓ Extract และ parse DMARC XML reports
- ✓ สร้างโฟลเดอร์อัตโนมัติถ้ายังไม่มี
- ✓ รองรับ SSL/TLS
- ✓ แสดงข้อมูลอีเมลและผลการตรวจสอบ DKIM/DMARC

## การติดตั้ง

1. ติดตั้ง dependencies:
```bash
# สำหรับ macOS/Linux (ใช้ python3 -m pip)
python3 -m pip install -r requirements.txt

# หรือใช้ pip3 ถ้ามีติดตั้งแล้ว
pip3 install -r requirements.txt
```

## การตั้งค่า

1. คัดลอกไฟล์ `env.example` เป็น `.env`:
```bash
cp env.example .env
```

2. แก้ไขไฟล์ `.env` ด้วยข้อมูลของคุณ:
```
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_USERNAME=your-email@gmail.com
IMAP_PASSWORD=your-app-password
```

### สำหรับ Gmail

- ต้องเปิดใช้งาน 2-Step Verification
- สร้าง App Password ได้ที่: https://myaccount.google.com/apppasswords
- ใช้ App Password แทนรหัสผ่านปกติ

### IMAP Servers อื่นๆ

- **Outlook/Hotmail**: `outlook.office365.com` (port 993)
- **Yahoo**: `imap.mail.yahoo.com` (port 993)
- **Custom IMAP**: ใช้ที่อยู่ server ของคุณเอง

## การใช้งาน
python3 imap_dkim_reader.py --move-dmarc --days 30   
python3 imap_dkim_reader.py --list-emails   
python3 imap_dkim_reader.py --extract-attachments    

### 1. อ่านอีเมลและแสดงผล (โหมดปกติ):

```bash
python3 imap_dkim_reader.py
```

### 2. ย้ายอีเมลที่มี DMARC ไปยังโฟลเดอร์ dmarc-report:

```bash
# ย้ายอีเมลทั้งหมดที่มี DMARC จาก INBOX ไปยังโฟลเดอร์ dmarc-report
python3 imap_dkim_reader.py --move-dmarc

# ระบุโฟลเดอร์ต้นทางและปลายทาง
python3 imap_dkim_reader.py --move-dmarc --source-folder INBOX --target-folder dmarc-report

# Scan เฉพาะอีเมลวันล่าสุด (เช่น 7 วันที่ผ่านมา)
python3 imap_dkim_reader.py --move-dmarc --days 7

# Scan อีเมล 30 วันล่าสุด และจำกัดจำนวนที่ตรวจสอบ
python3 imap_dkim_reader.py --move-dmarc --days 30 --limit 100

# โหมดทดสอบ (แสดงผลเฉยๆ ไม่ย้ายจริง)
python3 imap_dkim_reader.py --move-dmarc --dry-run

# Scan อีเมลวันล่าสุดพร้อม dry-run
python3 imap_dkim_reader.py --move-dmarc --days 1 --dry-run
```

### 3. แสดงรายการอีเมลในโฟลเดอร์ dmarc-report:

```bash
# แสดงรายการอีเมลทั้งหมดในโฟลเดอร์ dmarc-report
python3 imap_dkim_reader.py --list-emails

# แสดงรายการอีเมล 7 วันล่าสุด
python3 imap_dkim_reader.py --list-emails --days 7

# แสดงรายการอีเมล 20 ฉบับแรก
python3 imap_dkim_reader.py --list-emails --limit 20

# แสดงรายการอีเมลจากโฟลเดอร์อื่น
python3 imap_dkim_reader.py --list-emails --target-folder INBOX --days 7
```

### 4. ดึง attachments จากอีเมลในโฟลเดอร์ dmarc-report แยกตามวัน:

```bash
# ดึง attachments จากโฟลเดอร์ dmarc-report ทั้งหมด
python3 imap_dkim_reader.py --extract-attachments

# ดึง attachments จากอีเมล 7 วันล่าสุด
python3 imap_dkim_reader.py --extract-attachments --days 7

# ระบุโฟลเดอร์ source และ output directory
python3 imap_dkim_reader.py --extract-attachments --source-folder dmarc-report --output-dir ./dmarc_attachments

# จำกัดจำนวนอีเมลที่ตรวจสอบ
python3 imap_dkim_reader.py --extract-attachments --days 30 --limit 50
```

Attachments จะถูกบันทึกในโครงสร้าง:
```
dmarc-report/
├── 2025-12-25/
│   ├── report.xml
│   └── report2.xml
├── 2025-12-26/
│   └── report.xml
└── 2025-12-27/
    └── report.xml
```

### 5. Process และสรุปผล DMARC XML reports:

```bash
# Process DMARC XML files ทั้งหมดในโฟลเดอร์ dmarc-report
python3 imap_dkim_reader.py --process-dmarc

# Process จากโฟลเดอร์อื่น
python3 imap_dkim_reader.py --process-dmarc --output-dir ./dmarc_attachments
```

สคริปต์จะ:
- Extract ไฟล์ zip/gz ออกมาเป็น XML
- Parse DMARC XML reports
- แสดงสรุปผลการตรวจสอบ:
  - SPF pass/fail statistics
  - DKIM pass/fail statistics
  - DMARC pass/fail statistics
  - Disposition (none/quarantine/reject)
  - รายละเอียดแต่ละ report

### 6. Web Dashboard สำหรับดู DMARC Reports:

```bash
# เริ่มต้น Flask web server
python3 dashboard.py

# หรือระบุ port
PORT=8080 python3 dashboard.py

# หรือระบุ DMARC directory
DMARC_DIR=./dmarc-report python3 dashboard.py
```

เปิดเว็บเบราว์เซอร์ไปที่: **http://localhost:5000**

Dashboard จะแสดง:
- 📊 สถิติรวม (SPF, DKIM, DMARC pass/fail rates)
- 📈 Progress bars สำหรับแต่ละ metrics
- 📋 ตารางรายงาน DMARC reports ทั้งหมด
- 🌐 สรุปผลตาม domain
- 🔄 ปุ่มรีเฟรชข้อมูล

### 7. ดู options ทั้งหมด:

```bash
python3 imap_dkim_reader.py --help
```

### ใช้งานเป็น module:

```python
from imap_dkim_reader import IMAPDKIMReader

# สร้าง reader
reader = IMAPDKIMReader(
    imap_server='imap.gmail.com',
    imap_port=993,
    username='your-email@gmail.com',
    password='your-app-password'
)

# เชื่อมต่อ
reader.connect()

# อ่านอีเมล (ตรวจสอบ DKIM และ DMARC อัตโนมัติ)
emails = reader.fetch_emails(folder='INBOX', limit=10, verify_dkim=True)

# อ่านอีเมล 7 วันล่าสุด
emails = reader.fetch_emails(folder='INBOX', limit=10, verify_dkim=True, days=7)

# แสดงอีเมล
reader.display_emails(emails)

# ย้ายอีเมลที่มี DMARC ไปยังโฟลเดอร์ dmarc-report
stats = reader.move_dmarc_emails(
    source_folder='INBOX',
    target_folder='dmarc-report',
    limit=100,
    days=7,  # Scan เฉพาะ 7 วันที่ผ่านมา
    dry_run=False  # False = ย้ายจริง, True = แสดงผลเฉยๆ
)
print(f"Moved {stats['moved']} emails with DMARC")

# แสดงรายการอีเมลในโฟลเดอร์ dmarc-report
emails = reader.list_emails_in_folder(
    folder='dmarc-report',
    limit=20,
    days=7  # แสดงอีเมล 7 วันล่าสุด
)

# ดึง attachments จากโฟลเดอร์ dmarc-report และบันทึกแยกตามวัน
stats = reader.save_attachments_by_date(
    folder='dmarc-report',
    output_base_dir='dmarc-report',
    days=30,  # ดึงจากอีเมล 30 วันล่าสุด
    limit=None  # ไม่จำกัดจำนวน
)
print(f"Saved {stats['total_saved']} attachments")

# Process และสรุปผล DMARC XML reports
summary = reader.process_dmarc_files('dmarc-report', extract=True)
reader.print_dmarc_summary(summary)

# สร้างโฟลเดอร์ใหม่
reader.create_folder('dmarc-report')

# ย้ายอีเมลเดียว
reader.move_email(email_id='123', source_folder='INBOX', target_folder='dmarc-report', subject='Test Email')

# ปิดการเชื่อมต่อ
reader.disconnect()
```

## ข้อมูลที่ได้จากอีเมล

- Subject
- From/To
- Date
- Message-ID
- DKIM-Signature (ถ้ามี)
- DMARC status (มีหรือไม่มี)
- Authentication-Results header
- ผลการตรวจสอบ DKIM:
  - Verified status
  - Domain
  - Selector
  - Algorithm

## ตัวอย่างผลลัพธ์

```
✓ Connected to imap.gmail.com successfully

Available folders:
  - INBOX
  - Sent
  - Drafts
  ...

✓ Selected folder: INBOX (42 messages)

================================================================================
Found 5 email(s)
================================================================================

[Email 1]
  ID: 123
  From: sender@example.com
  To: your-email@gmail.com
  Subject: Test Email
  Date: Mon, 1 Jan 2024 12:00:00 +0700
  Message-ID: <example@example.com>
  DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; ...
  DMARC: ✓ Found
  DKIM Status: ✓ VERIFIED
    Domain: example.com
    Selector: default
    Algorithm: rsa-sha256
    Message: DKIM signature verified successfully
--------------------------------------------------------------------------------
```

## ตัวอย่างการย้ายอีเมล DMARC

```
$ python3 imap_dkim_reader.py --move-dmarc --dry-run

================================================================================
DMARC Email Mover
================================================================================
⚠️  DRY RUN MODE - No emails will be moved
Source folder: INBOX
Target folder: dmarc-report

✓ Connected to imap.gmail.com successfully
✓ Selected folder: INBOX (42 messages)

Scanning emails in INBOX for DMARC...
  [DRY RUN] Would move: Test Email with DMARC
  [DRY RUN] Would move: Another DMARC Email

================================================================================
Summary:
================================================================================
Total emails checked: 42
DMARC emails found: 2
Would move: 2 emails

DMARC emails:
  - Test Email with DMARC
    From: sender@example.com
  - Another DMARC Email
    From: another@example.com
```

## คำอธิบายเพิ่มเติม

### DMARC คืออะไร?

DMARC (Domain-based Message Authentication, Reporting & Conformance) เป็นมาตรฐาน email authentication ที่ช่วยป้องกัน email spoofing โดยตรวจสอบว่าอีเมลถูกส่งจากโดเมนที่ถูกต้องหรือไม่

### การตรวจสอบ DMARC

สคริปต์จะตรวจสอบ DMARC จากหลายแหล่ง:

**1. Email Headers:**
- `Authentication-Results` header
- `ARC-Authentication-Results` header  
- `Received` headers

**2. DMARC Report Emails:**
- Subject ที่มีคำว่า "dmarc", "report domain", "report-id"
- Body content ที่มี "Report Domain:", "Report-ID:", "Submitter:"
- XML tags เช่น `<feedback>`, `<record>` ใน DMARC aggregate reports

**ตัวอย่าง DMARC Report Email:**
```
Subject: Report Domain: kon.in.th; Submitter: Mail.Ru; Report-ID: 72495910218435654001766534400
```

อีเมลประเภทนี้จะถูกย้ายไปยังโฟลเดอร์ dmarc-report อัตโนมัติ

### การย้ายอีเมล

เมื่อใช้ `--move-dmarc` สคริปต์จะ:
1. ค้นหาอีเมลทั้งหมดในโฟลเดอร์ที่ระบุ
2. ตรวจสอบว่าอีเมลแต่ละฉบับเป็น DMARC report email จริงๆ (ไม่ใช่อีเมลที่ผ่าน DMARC check)
3. สร้างโฟลเดอร์ปลายทางถ้ายังไม่มี
4. ย้ายอีเมลที่มี DMARC ไปยังโฟลเดอร์ dmarc-report
5. แสดง ID และ Subject ของอีเมลที่ย้ายสำเร็จ

**หมายเหตุ**: สคริปต์จะตรวจสอบเฉพาะ DMARC report emails จริงๆ โดยดูจาก:
- Subject ที่มี pattern "Report Domain:", "Report-ID:", "Submitter:"
- Attachments ที่เป็น zip/gz/xml ที่มีชื่อรูปแบบ DMARC report
- XML structure ใน body ที่มี tags เช่น `<feedback>`, `<report_metadata>`

**คำแนะนำ**: ใช้ `--dry-run` เพื่อทดสอบก่อนย้ายจริง

## License

MIT

