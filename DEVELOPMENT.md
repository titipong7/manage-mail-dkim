# Development Steps - IMAP DKIM/DMARC Email Reader

เอกสารสรุปขั้นตอนการพัฒนาโปรเจกต์

## Phase 1: Basic IMAP DKIM Email Reader

### Step 1.1: สร้างโครงสร้างพื้นฐาน
- ✅ สร้าง `imap_dkim_reader.py` พร้อมคลาส `DKIMVerifier` และ `IMAPDKIMReader`
- ✅ เพิ่มฟังก์ชันพื้นฐาน:
  - `connect()` - เชื่อมต่อ IMAP server
  - `list_folders()` - แสดงรายการโฟลเดอร์
  - `select_folder()` - เลือกโฟลเดอร์
  - `fetch_emails()` - ดึงอีเมล
  - `display_emails()` - แสดงอีเมล

### Step 1.2: DKIM Verification
- ✅ เพิ่มการตรวจสอบลายเซ็น DKIM
- ✅ แสดงข้อมูล DKIM (domain, selector, algorithm)
- ✅ ติดตั้ง dependencies: `dkimpy`, `python-dotenv`

### Step 1.3: Configuration
- ✅ สร้าง `requirements.txt`
- ✅ สร้าง `env.example` สำหรับการตั้งค่า
- ✅ อ่านค่า configuration จาก `.env` file

## Phase 2: DMARC Support

### Step 2.1: DMARC Detection
- ✅ เพิ่มฟังก์ชัน `has_dmarc()` เพื่อตรวจสอบ DMARC
- ✅ ตรวจสอบจากหลายแหล่ง:
  - Authentication-Results header
  - ARC-Authentication-Results header
  - Received headers
  - Subject (สำหรับ DMARC report emails)
  - Body content (สำหรับ DMARC report emails)
  - XML tags (`<feedback>`, `<record>`)

### Step 2.2: Move DMARC Emails
- ✅ เพิ่มฟังก์ชัน `move_dmarc_emails()` เพื่อย้ายอีเมล DMARC
- ✅ เพิ่มฟังก์ชัน `create_folder()` สำหรับสร้างโฟลเดอร์
- ✅ เพิ่มฟังก์ชัน `move_email()` สำหรับย้ายอีเมลเดียว
- ✅ เพิ่ม command line option `--move-dmarc`
- ✅ เพิ่ม `--dry-run` mode สำหรับทดสอบ

### Step 2.3: Improved DMARC Detection
- ✅ ปรับปรุง `has_dmarc()` ให้ตรวจสอบเฉพาะ DMARC report emails จริงๆ
- ✅ ตรวจสอบ Subject patterns ที่ชัดเจน ("Report Domain:", "Report-ID:", "Submitter:")
- ✅ ตรวจสอบ Attachments (zip/gz/xml)
- ✅ ตรวจสอบ XML structure ใน body
- ✅ ลบการตรวจสอบ Authentication-Results header ที่มี `dmarc=` (เพราะเป็นผลการตรวจสอบ ไม่ใช่ report email)

## Phase 3: Date-based Filtering

### Step 3.1: Date Search Support
- ✅ เพิ่มฟังก์ชัน `get_date_search_criteria()` สำหรับสร้าง IMAP search criteria
- ✅ รองรับการค้นหาตามวันที่ (SINCE)
- ✅ เพิ่ม parameter `days` ใน `fetch_emails()` และ `move_dmarc_emails()`
- ✅ เพิ่ม command line option `--days`

### Step 3.2: Enhanced Output
- ✅ แสดง ID และ Subject เมื่อย้ายอีเมลสำเร็จ
- ✅ ปรับปรุงการแสดงผลให้แสดงข้อมูลครบถ้วน

## Phase 4: Attachment Extraction

### Step 4.1: Extract Attachments
- ✅ เพิ่มฟังก์ชัน `extract_attachments()` สำหรับดึง attachments จากอีเมล
- ✅ เพิ่มฟังก์ชัน `get_email_date()` สำหรับดึงวันที่จากอีเมล
- ✅ เพิ่มฟังก์ชัน `sanitize_filename()` สำหรับทำความสะอาดชื่อไฟล์
- ✅ เพิ่มฟังก์ชัน `save_attachments_by_date()` สำหรับบันทึก attachments แยกตามวัน

### Step 4.2: Organized Storage
- ✅ บันทึก attachments ในโครงสร้าง `YYYY-MM-DD/`
- ✅ ใช้ชื่อไฟล์เดิมจากอีเมล (ทำความสะอาดเฉพาะอักขระที่ไม่ปลอดภัย)
- ✅ เพิ่ม command line option `--extract-attachments`

### Step 4.3: Skip Duplicate Extraction
- ✅ ตรวจสอบว่าไฟล์ถูก extract ไปแล้วหรือไม่
- ✅ เปรียบเทียบขนาดไฟล์เพื่อยืนยัน
- ✅ ข้ามไฟล์ที่ extract แล้ว (ไม่ extract ซ้ำ)
- ✅ เพิ่ม `total_skipped` ใน statistics

## Phase 5: DMARC XML Processing

### Step 5.1: Archive Extraction
- ✅ เพิ่มฟังก์ชัน `extract_archive()` สำหรับ extract zip/gz files
- ✅ รองรับ ZIP และ GZ formats
- ✅ Extract อัตโนมัติ nested archives

### Step 5.2: XML Parsing
- ✅ เพิ่มฟังก์ชัน `parse_dmarc_xml()` สำหรับ parse DMARC XML reports
- ✅ Parse report_metadata (org_name, email, report_id, date_range)
- ✅ Parse policy_published (domain, adkim, aspf, p, sp, pct)
- ✅ Parse records (row, identifiers, auth_results)
- ✅ สรุปผลการตรวจสอบ (SPF, DKIM, DMARC pass/fail)

### Step 5.3: Batch Processing
- ✅ เพิ่มฟังก์ชัน `process_dmarc_files()` สำหรับ process ไฟล์ทั้งหมด
- ✅ เพิ่มฟังก์ชัน `print_dmarc_summary()` สำหรับแสดงสรุปผล
- ✅ เพิ่ม command line option `--process-dmarc`

## Phase 6: Folder Renaming & Listing

### Step 6.1: Rename Folder
- ✅ เปลี่ยนชื่อโฟลเดอร์ default จาก `dmarc` เป็น `dmarc-report`
- ✅ อัปเดตทุกที่ที่ใช้ `dmarc` folder

### Step 6.2: Email Listing
- ✅ เพิ่มฟังก์ชัน `list_emails_in_folder()` สำหรับแสดงรายการอีเมล
- ✅ แสดง ID, From, Subject, Date
- ✅ รองรับการ filter ตามวันที่และจำนวน
- ✅ เพิ่ม command line option `--list-emails`

## Phase 7: Bug Fixes & Improvements

### Step 7.1: Fix Import Errors
- ✅ แก้ไข type hint `email.message.Message` → `Message`
- ✅ เพิ่ม import `from email.message import Message`

### Step 7.2: Fix IMAP Errors
- ✅ แปลง `email_id` จาก bytes เป็น string ก่อนใช้ใน IMAP commands
- ✅ เพิ่ม error handling สำหรับ "Invalid messageset"
- ✅ จัดการ "Too many invalid IMAP commands" error
- ✅ ข้ามอีเมลที่ถูกลบหรือย้ายไปแล้ว

### Step 7.3: Enhanced Error Handling
- ✅ เพิ่ม try-except blocks ในทุกฟังก์ชัน
- ✅ แสดง error messages ที่เข้าใจง่าย
- ✅ ไม่หยุดทำงานเมื่อพบ error แต่ข้ามไปต่อ

## Phase 8: Documentation

### Step 8.1: README
- ✅ สร้าง README.md พร้อมคำแนะนำการใช้งาน
- ✅ อัปเดต README เมื่อเพิ่มฟีเจอร์ใหม่
- ✅ เพิ่มตัวอย่างการใช้งาน

### Step 8.2: Code Documentation
- ✅ เพิ่ม docstrings ในทุกฟังก์ชัน
- ✅ อธิบาย parameters และ return values

## สรุปฟีเจอร์ทั้งหมด

### Command Line Options:
1. `--move-dmarc` - ย้ายอีเมล DMARC ไปยังโฟลเดอร์ dmarc-report
2. `--extract-attachments` - ดึง attachments และบันทึกแยกตามวัน
3. `--process-dmarc` - Process และ parse DMARC XML reports
4. `--list-emails` - แสดงรายการอีเมลในโฟลเดอร์
5. `--days N` - Scan เฉพาะ N วันที่ผ่านมา
6. `--limit N` - จำกัดจำนวนอีเมล
7. `--dry-run` - ทดสอบโดยไม่ย้ายจริง
8. `--source-folder FOLDER` - ระบุโฟลเดอร์ต้นทาง
9. `--target-folder FOLDER` - ระบุโฟลเดอร์ปลายทาง
10. `--output-dir DIR` - ระบุโฟลเดอร์ output

### ฟังก์ชันหลัก:

#### DKIM Verification:
- `DKIMVerifier.verify_dkim()` - ตรวจสอบลายเซ็น DKIM

#### IMAP Operations:
- `connect()` - เชื่อมต่อ IMAP server
- `list_folders()` - แสดงรายการโฟลเดอร์
- `select_folder()` - เลือกโฟลเดอร์
- `fetch_emails()` - ดึงอีเมล
- `list_emails_in_folder()` - แสดงรายการอีเมล

#### DMARC Operations:
- `has_dmarc()` - ตรวจสอบ DMARC
- `move_dmarc_emails()` - ย้ายอีเมล DMARC
- `create_folder()` - สร้างโฟลเดอร์
- `move_email()` - ย้ายอีเมลเดียว

#### Attachment Operations:
- `extract_attachments()` - ดึง attachments
- `save_attachments_by_date()` - บันทึก attachments แยกตามวัน
- `get_email_date()` - ดึงวันที่จากอีเมล
- `sanitize_filename()` - ทำความสะอาดชื่อไฟล์

#### DMARC XML Processing:
- `extract_archive()` - Extract zip/gz files
- `parse_dmarc_xml()` - Parse DMARC XML
- `process_dmarc_files()` - Process ไฟล์ทั้งหมด
- `print_dmarc_summary()` - แสดงสรุปผล

#### Utility Functions:
- `decode_mime_words()` - ถอดรหัส MIME encoded headers
- `get_date_search_criteria()` - สร้าง IMAP search criteria

## Dependencies

- `dkimpy==1.1.5` - สำหรับตรวจสอบ DKIM signatures
- `python-dotenv==1.0.0` - สำหรับอ่าน .env file
- `flask==3.0.0` - สำหรับ dashboard (เพิ่มในอนาคต)

## การทดสอบ

1. ✅ Syntax check - `python3 -c "import imap_dkim_reader"`
2. ✅ Linter check - ตรวจสอบด้วย linter
3. ✅ Import check - ทดสอบการ import modules

## Notes

- โฟลเดอร์ default เปลี่ยนจาก `dmarc` เป็น `dmarc-report`
- ตรวจสอบเฉพาะ DMARC report emails จริงๆ (ไม่ใช่อีเมลที่ผ่าน DMARC check)
- รองรับการ extract attachments ซ้ำโดยข้ามไฟล์ที่มีอยู่แล้ว
- จัดการ IMAP errors อย่างเหมาะสม

## Future Enhancements

- [ ] Web dashboard สำหรับดู DMARC reports
- [ ] Export reports เป็น CSV/JSON
- [ ] Email notification เมื่อพบ DMARC issues
- [ ] Database storage สำหรับ reports
- [ ] Chart/Graph visualization
- [ ] Multi-domain support
- [ ] Automated scheduling
