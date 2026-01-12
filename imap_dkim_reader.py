#!/usr/bin/env python3
"""
IMAP DKIM Email Reader
อ่านอีเมลจาก IMAP และตรวจสอบลายเซ็น DKIM/DMARC
ย้ายอีเมลที่มี DMARC ไปยังโฟลเดอร์ dmarc
"""

import imaplib
import email
from email.message import Message
from email.header import decode_header
import dkim
from dkim.util import parse_tag_value
import socket
import ssl
from typing import Optional, Dict, List, Any
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
import re
import zipfile
import gzip
import xml.etree.ElementTree as ET
from pathlib import Path

# โหลด environment variables
load_dotenv()


class DKIMVerifier:
    """คลาสสำหรับตรวจสอบลายเซ็น DKIM"""
    
    def verify_dkim(self, raw_email: bytes) -> Dict[str, any]:
        """
        ตรวจสอบลายเซ็น DKIM ของอีเมล
        
        Args:
            raw_email: อีเมลในรูปแบบ bytes
            
        Returns:
            dict: ผลการตรวจสอบ DKIM
        """
        try:
            # ตรวจสอบลายเซ็น DKIM
            result = dkim.verify(raw_email)
            
            if result:
                # แยกข้อมูลจาก DKIM signature
                msg = email.message_from_bytes(raw_email)
                dkim_header = msg.get('DKIM-Signature', '')
                
                if dkim_header:
                    dkim_data = parse_tag_value(dkim_header)
                    return {
                        'verified': True,
                        'domain': dkim_data.get('d', 'Unknown'),
                        'selector': dkim_data.get('s', 'Unknown'),
                        'algorithm': dkim_data.get('a', 'Unknown'),
                        'signature': dkim_data.get('b', '')[:50] + '...' if len(dkim_data.get('b', '')) > 50 else dkim_data.get('b', ''),
                        'message': 'DKIM signature verified successfully'
                    }
                else:
                    return {
                        'verified': False,
                        'message': 'No DKIM signature found in email'
                    }
            else:
                return {
                    'verified': False,
                    'message': 'DKIM signature verification failed'
                }
        except Exception as e:
            return {
                'verified': False,
                'message': f'DKIM verification error: {str(e)}'
            }


class IMAPDKIMReader:
    """คลาสสำหรับอ่านอีเมลจาก IMAP และตรวจสอบ DKIM"""
    
    def __init__(self, 
                 imap_server: str = None,
                 imap_port: int = 993,
                 username: str = None,
                 password: str = None,
                 use_ssl: bool = True):
        """
        Initialize IMAP connection
        
        Args:
            imap_server: ที่อยู่ IMAP server (เช่น imap.gmail.com) - optional สำหรับใช้ process DMARC files เท่านั้น
            imap_port: พอร์ต IMAP (default: 993 สำหรับ SSL)
            username: ชื่อผู้ใช้
            password: รหัสผ่าน
            use_ssl: ใช้ SSL/TLS หรือไม่
        """
        self.imap_server = imap_server or os.getenv('IMAP_SERVER')
        self.imap_port = imap_port
        self.username = username or os.getenv('IMAP_USERNAME')
        self.password = password or os.getenv('IMAP_PASSWORD')
        self.use_ssl = use_ssl
        self.imap = None
        self.verifier = DKIMVerifier()
    
    def connect(self):
        """เชื่อมต่อกับ IMAP server"""
        if not self.imap_server:
            raise Exception("IMAP server not configured. Cannot connect without IMAP server address.")
        try:
            if self.use_ssl:
                self.imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            else:
                self.imap = imaplib.IMAP4(self.imap_server, self.imap_port)
            
            # Login
            if self.username and self.password:
                self.imap.login(self.username, self.password)
                print(f"✓ Connected to {self.imap_server} successfully")
            else:
                raise ValueError("Username and password are required")
                
        except imaplib.IMAP4.error as e:
            raise Exception(f"IMAP connection error: {str(e)}")
        except socket.gaierror as e:
            raise Exception(f"DNS resolution error: {str(e)}")
        except ssl.SSLError as e:
            raise Exception(f"SSL error: {str(e)}")
    
    def list_folders(self) -> List[str]:
        """แสดงรายการโฟลเดอร์อีเมล"""
        if not self.imap:
            raise Exception("Not connected to IMAP server")
        
        status, folders = self.imap.list()
        if status == 'OK':
            folder_list = []
            for folder in folders:
                # แปลงจาก bytes เป็น string และแยกชื่อโฟลเดอร์
                folder_str = folder.decode('utf-8')
                folder_name = folder_str.split(' "/" ')[-1].strip('"')
                folder_list.append(folder_name)
            return folder_list
        else:
            raise Exception(f"Failed to list folders: {folders}")
    
    def select_folder(self, folder: str = 'INBOX'):
        """เลือกโฟลเดอร์ที่จะอ่านอีเมล"""
        if not self.imap:
            raise Exception("Not connected to IMAP server")
        
        status, messages = self.imap.select(folder)
        if status == 'OK':
            count = int(messages[0])
            print(f"✓ Selected folder: {folder} ({count} messages)")
            return count
        else:
            raise Exception(f"Failed to select folder: {messages}")
    
    def decode_mime_words(self, s):
        """ถอดรหัส MIME encoded header"""
        if not s:
            return ''
        decoded = decode_header(s)
        return ''.join([text.decode(charset or 'utf-8') if isinstance(text, bytes) else text 
                       for text, charset in decoded])
    
    def get_date_search_criteria(self, days: int = None) -> str:
        """
        สร้าง IMAP search criteria สำหรับค้นหาตามวันที่
        
        Args:
            days: จำนวนวันที่ย้อนหลัง (None = ทั้งหมด)
            
        Returns:
            str: IMAP search criteria string
        """
        if days is None or days <= 0:
            return 'ALL'
        
        # คำนวณวันที่
        target_date = datetime.now() - timedelta(days=days)
        # รูปแบบวันที่สำหรับ IMAP: DD-MMM-YYYY (เช่น 01-Jan-2024)
        date_str = target_date.strftime('%d-%b-%Y')
        # ใช้ SINCE เพื่อหาอีเมลตั้งแต่วันที่นั้นเป็นต้นมา
        return f'SINCE {date_str}'
    
    def has_dmarc(self, msg: Message) -> bool:
        """
        ตรวจสอบว่าอีเมลเป็น DMARC report email หรือไม่
        (ไม่ใช่แค่อีเมลที่ผ่าน DMARC check แต่เป็น report email จริงๆ)
        
        Args:
            msg: Email message object
            
        Returns:
            bool: True ถ้าเป็น DMARC report email, False ถ้าไม่ใช่
        """
        subject = self.decode_mime_words(msg.get('Subject', ''))
        subject_lower = subject.lower()
        
        # ตรวจสอบ Subject สำหรับ DMARC report emails - ต้องมี pattern ที่ชัดเจน
        # DMARC report emails มักมีรูปแบบ: "Report Domain: domain.com; Submitter: ...; Report-ID: ..."
        dmarc_report_patterns = [
            r'report\s+domain\s*:',
            r'report-id\s*:',
            r'submitter\s*:',
            r'dmarc\s+aggregate\s+report',
            r'dmarc\s+failure\s+report',
            r'domain-based\s+message\s+authentication.*report'
        ]
        
        for pattern in dmarc_report_patterns:
            if re.search(pattern, subject_lower):
                # ตรวจสอบให้แน่ใจว่ามีรายละเอียดครบถ้วน
                if 'report domain' in subject_lower or 'report-id' in subject_lower:
                    return True
        
        # ตรวจสอบ attachments - DMARC reports มักมีไฟล์ zip/gz/xml
        has_dmarc_attachment = False
        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = part.get('Content-Disposition', '')
                if 'attachment' in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        filename_lower = filename.lower()
                        # ตรวจสอบชื่อไฟล์ที่มี pattern ของ DMARC report
                        if (filename_lower.endswith('.zip') or 
                            filename_lower.endswith('.gz') or
                            filename_lower.endswith('.xml')):
                            # ตรวจสอบชื่อไฟล์ที่มักใช้ใน DMARC reports
                            # เช่น: domain.com!report-id.xml.gz หรือ domain.com!domain.com!timestamp!timestamp.zip
                            if ('!' in filename_lower and 
                                (filename_lower.endswith('.zip') or filename_lower.endswith('.gz') or 
                                 'xml' in filename_lower)):
                                has_dmarc_attachment = True
                                break
        
        # ตรวจสอบใน body content (สำหรับ DMARC report emails ที่ส่ง XML ใน body)
        try:
            body_text = ''
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == 'text/plain' or content_type == 'text/html' or content_type == 'application/xml' or content_type == 'text/xml':
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body_text += payload.decode('utf-8', errors='ignore')
                        except:
                            pass
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode('utf-8', errors='ignore')
                except:
                    pass
            
            # ตรวจสอบ XML structure ของ DMARC report
            if body_text:
                body_lower = body_text.lower()
                # ต้องมี XML tags ที่เฉพาะเจาะจงสำหรับ DMARC report
                has_feedback_tag = '<feedback' in body_lower
                has_report_metadata = '<report_metadata' in body_lower
                has_policy_published = '<policy_published' in body_lower
                has_record_tag = '<record>' in body_lower
                
                # ถ้ามี XML structure ของ DMARC report
                if has_feedback_tag and (has_report_metadata or has_policy_published):
                    return True
                
                # หรือถ้ามี pattern ของ DMARC report ใน text format
                if ('report domain:' in body_lower and 
                    'report-id:' in body_lower and 
                    'submitter:' in body_lower):
                    return True
        except Exception:
            pass
        
        # ถ้ามี attachment ที่เป็น DMARC report
        if has_dmarc_attachment:
            return True
        
        # ไม่ใช่ DMARC report email
        return False
    
    def create_folder(self, folder_name: str) -> bool:
        """
        สร้างโฟลเดอร์ใหม่ใน mail server
        
        Args:
            folder_name: ชื่อโฟลเดอร์ที่ต้องการสร้าง
            
        Returns:
            bool: True ถ้าสร้างสำเร็จหรือมีอยู่แล้ว, False ถ้าสร้างไม่สำเร็จ
        """
        if not self.imap:
            raise Exception("Not connected to IMAP server")
        
        try:
            # พยายามสร้างโฟลเดอร์
            status, response = self.imap.create(folder_name)
            if status == 'OK':
                print(f"✓ Created folder: {folder_name}")
                return True
            else:
                # ถ้าโฟลเดอร์มีอยู่แล้วก็ไม่เป็นไร
                if 'already exists' in str(response).lower() or 'ALREADYEXISTS' in str(response):
                    print(f"✓ Folder {folder_name} already exists")
                    return True
                else:
                    print(f"✗ Failed to create folder {folder_name}: {response}")
                    return False
        except Exception as e:
            # ถ้าโฟลเดอร์มีอยู่แล้วจะเกิด exception บางครั้ง
            if 'already exists' in str(e).lower() or 'ALREADYEXISTS' in str(e).lower():
                print(f"✓ Folder {folder_name} already exists")
                return True
            print(f"✗ Error creating folder {folder_name}: {str(e)}")
            return False
    
    def move_email(self, email_id: str, source_folder: str, target_folder: str, subject: str = None) -> bool:
        """
        ย้ายอีเมลจากโฟลเดอร์หนึ่งไปยังอีกโฟลเดอร์หนึ่ง
        
        Args:
            email_id: ID ของอีเมลที่ต้องการย้าย
            source_folder: โฟลเดอร์ต้นทาง
            target_folder: โฟลเดอร์ปลายทาง
            subject: Subject ของอีเมล (ถ้ามี)
            
        Returns:
            bool: True ถ้าย้ายสำเร็จ, False ถ้าย้ายไม่สำเร็จ
        """
        if not self.imap:
            raise Exception("Not connected to IMAP server")
        
        try:
            # แปลง email_id เป็น string (ถ้าเป็น bytes)
            email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
            
            # ดึง subject ถ้ายังไม่มี
            if subject is None:
                try:
                    status, _ = self.imap.select(source_folder)
                    if status == 'OK':
                        status, msg_data = self.imap.fetch(email_id_str, '(RFC822.HEADER)')
                        if status == 'OK' and msg_data:
                            msg = email.message_from_bytes(msg_data[0][1])
                            subject = self.decode_mime_words(msg.get('Subject', 'No Subject'))
                except:
                    subject = 'Unknown'
            
            # เลือกโฟลเดอร์ต้นทาง
            status, _ = self.imap.select(source_folder)
            if status != 'OK':
                print(f"✗ Failed to select source folder: {source_folder}")
                return False
            
            # ย้ายอีเมล (ใช้ COPY แล้ว DELETE)
            status, response = self.imap.copy(email_id_str, target_folder)
            if status == 'OK':
                # ลบอีเมลจากโฟลเดอร์เดิม
                status, response = self.imap.store(email_id_str, '+FLAGS', '\\Deleted')
                if status == 'OK':
                    # บังคับให้ลบจริงๆ (EXPUNGE)
                    self.imap.expunge()
                    # แสดง subject และ id
                    subject_display = subject[:60] + '...' if len(subject) > 60 else subject
                    print(f"✓ Moved email ID: {email_id_str} | Subject: {subject_display} | From: {source_folder} to {target_folder}")
                    return True
                else:
                    print(f"✗ Failed to delete email from source: {response}")
                    return False
            else:
                # ตรวจสอบว่าเป็น invalid messageset หรือไม่
                if 'invalid messageset' in str(response).lower():
                    # อีเมลอาจถูกลบหรือย้ายไปแล้ว
                    print(f"  ⚠️  Email {email_id_str} may have been moved or deleted already")
                else:
                    print(f"✗ Failed to copy email: {response}")
                return False
                
        except imaplib.IMAP4.error as e:
            # IMAP error - อาจเป็นเพราะอีเมลถูกลบหรือย้ายไปแล้ว
            if 'invalid messageset' in str(e).lower() or 'too many invalid' in str(e).lower():
                print(f"  ⚠️  Email {email_id_str} may have been moved or deleted: {str(e)}")
            else:
                print(f"✗ IMAP error moving email {email_id_str}: {str(e)}")
            return False
        except Exception as e:
            print(f"✗ Error moving email {email_id_str}: {str(e)}")
            return False
    
    def move_dmarc_emails(self, 
                         source_folder: str = 'INBOX',
                         target_folder: str = 'dmarc-report',
                         limit: int = None,
                         days: int = None,
                         dry_run: bool = False) -> Dict[str, any]:
        """
        ค้นหาและย้ายอีเมลที่มี DMARC ไปยังโฟลเดอร์ dmarc
        
        Args:
            source_folder: โฟลเดอร์ที่ต้องการค้นหา (default: INBOX)
            target_folder: โฟลเดอร์ปลายทาง (default: dmarc)
            limit: จำกัดจำนวนอีเมลที่ตรวจสอบ (None = ทั้งหมด)
            days: จำนวนวันที่ย้อนหลังที่ต้องการ scan (None = ทั้งหมด)
            dry_run: True = แสดงผลเฉยๆ ไม่ย้ายจริง
            
        Returns:
            dict: สถิติการย้ายอีเมล
        """
        if not self.imap:
            self.connect()
        
        # สร้างโฟลเดอร์ปลายทางถ้ายังไม่มี
        if not dry_run:
            self.create_folder(target_folder)
        
        # เลือกโฟลเดอร์ต้นทาง
        self.select_folder(source_folder)
        
        # สร้าง search criteria ตามวันที่
        search_criteria = self.get_date_search_criteria(days)
        
        # ค้นหาอีเมลตาม criteria
        status, messages = self.imap.search(None, search_criteria)
        if status != 'OK':
            raise Exception(f"Failed to search emails: {messages}")
        
        email_ids = messages[0].split()
        if limit:
            email_ids = email_ids[:limit]
        
        stats = {
            'total_checked': 0,
            'dmarc_found': 0,
            'moved': 0,
            'failed': 0,
            'emails': []
        }
        
        date_info = f" (last {days} days)" if days else ""
        print(f"\nScanning emails in {source_folder}{date_info} for DMARC...")
        
        for email_id in email_ids:
            try:
                stats['total_checked'] += 1
                
                # แปลง email_id เป็น string (ถ้าเป็น bytes)
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                
                # ดึงอีเมล
                status, msg_data = self.imap.fetch(email_id_str, '(RFC822)')
                if status != 'OK':
                    # ถ้าเกิด error อาจเป็นเพราะอีเมลถูกลบหรือย้ายไปแล้ว ข้ามไป
                    continue
                
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # ตรวจสอบ DMARC
                if self.has_dmarc(msg):
                    stats['dmarc_found'] += 1
                    
                    email_subject = self.decode_mime_words(msg.get('Subject', 'No Subject'))
                    email_info = {
                        'id': email_id_str,
                        'subject': email_subject,
                        'from': self.decode_mime_words(msg.get('From', 'Unknown')),
                        'date': msg.get('Date', 'Unknown'),
                    }
                    stats['emails'].append(email_info)
                    
                    # ย้ายอีเมล
                    if not dry_run:
                        if self.move_email(email_id_str, source_folder, target_folder, subject=email_subject):
                            stats['moved'] += 1
                        else:
                            stats['failed'] += 1
                    else:
                        print(f"  [DRY RUN] Would move: ID: {email_id_str} | Subject: {email_subject[:50]}")
                        stats['moved'] += 1
                
            except imaplib.IMAP4.error as e:
                # IMAP error - อาจเป็นเพราะอีเมลถูกลบหรือย้ายไปแล้ว
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                # ไม่แสดง error สำหรับอีเมลที่ถูกลบ/ย้ายไปแล้ว (เป็นเรื่องปกติ)
                if 'invalid messageset' in str(e).lower() or 'too many invalid' in str(e).lower():
                    # หยุดการประมวลผลถ้าเกิด "Too many invalid IMAP commands" เพื่อป้องกันการ disconnect
                    print(f"\n⚠️  Stopping: Too many IMAP errors. Some emails may have been deleted or moved.")
                    break
                else:
                    print(f"  ⚠️  Skipped email {email_id_str}: {str(e)}")
                stats['failed'] += 1
                continue
            except Exception as e:
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                # ตรวจสอบว่ามี "Too many invalid IMAP commands" หรือไม่
                if 'too many invalid' in str(e).lower():
                    print(f"\n⚠️  Stopping: Too many IMAP errors. Some emails may have been deleted or moved.")
                    break
                print(f"  ⚠️  Error processing email {email_id_str}: {str(e)}")
                stats['failed'] += 1
                continue
        
        return stats
    
    def fetch_emails(self, 
                     folder: str = 'INBOX',
                     limit: int = 10,
                     verify_dkim: bool = True,
                     days: int = None) -> List[Dict]:
        """
        ดึงอีเมลจากโฟลเดอร์ที่กำหนด
        
        Args:
            folder: โฟลเดอร์ที่ต้องการอ่าน (default: INBOX)
            limit: จำนวนอีเมลที่ต้องการอ่าน (default: 10)
            verify_dkim: ตรวจสอบ DKIM หรือไม่ (default: True)
            days: จำนวนวันที่ย้อนหลังที่ต้องการ scan (None = ทั้งหมด)
            
        Returns:
            list: รายการอีเมลพร้อมข้อมูล DKIM
        """
        if not self.imap:
            self.connect()
        
        self.select_folder(folder)
        
        # สร้าง search criteria ตามวันที่
        search_criteria = self.get_date_search_criteria(days)
        
        # ค้นหาอีเมลตาม criteria (เรียงจากใหม่ไปเก่า)
        status, messages = self.imap.search(None, search_criteria)
        if status != 'OK':
            raise Exception(f"Failed to search emails: {messages}")
        
        email_ids = messages[0].split()
        email_ids.reverse()  # เรียงจากใหม่ไปเก่า
        
        emails = []
        
        for email_id in email_ids[:limit]:
            try:
                # แปลง email_id เป็น string (ถ้าเป็น bytes)
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                
                # ดึงอีเมลทั้งฉบับ (RFC822)
                status, msg_data = self.imap.fetch(email_id_str, '(RFC822)')
                
                if status != 'OK':
                    continue
                
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # แปลงข้อมูลอีเมล
                email_info = {
                    'id': email_id_str,
                    'subject': self.decode_mime_words(msg.get('Subject', 'No Subject')),
                    'from': self.decode_mime_words(msg.get('From', 'Unknown')),
                    'to': self.decode_mime_words(msg.get('To', 'Unknown')),
                    'date': msg.get('Date', 'Unknown'),
                    'message_id': msg.get('Message-ID', 'Unknown'),
                    'dkim_signature': msg.get('DKIM-Signature', None),
                    'authentication_results': msg.get('Authentication-Results', None),
                    'raw_email': raw_email,  # เก็บ raw email สำหรับย้าย
                    'msg': msg,  # เก็บ message object
                }
                
                # ตรวจสอบ DMARC
                email_info['has_dmarc'] = self.has_dmarc(msg)
                
                # ตรวจสอบ DKIM หากต้องการ
                if verify_dkim:
                    dkim_result = self.verifier.verify_dkim(raw_email)
                    email_info['dkim'] = dkim_result
                
                emails.append(email_info)
                
            except imaplib.IMAP4.error as e:
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                # ตรวจสอบว่าเป็น invalid messageset หรือไม่
                if 'invalid messageset' in str(e).lower() or 'too many invalid' in str(e).lower():
                    # อีเมลอาจถูกลบหรือย้ายไปแล้ว ข้ามไป
                    continue
                else:
                    print(f"  ⚠️  Error processing email {email_id_str}: {str(e)}")
                continue
            except Exception as e:
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                # ตรวจสอบว่าเป็น IMAP error หรือไม่
                if 'invalid messageset' in str(e).lower() or 'too many invalid' in str(e).lower():
                    # อีเมลอาจถูกลบหรือย้ายไปแล้ว ข้ามไป
                    continue
                print(f"  ⚠️  Error processing email {email_id_str}: {str(e)}")
                continue
        
        return emails
    
    def display_emails(self, emails: List[Dict]):
        """แสดงอีเมลในรูปแบบที่อ่านง่าย"""
        print("\n" + "="*80)
        print(f"Found {len(emails)} email(s)")
        print("="*80)
        
        for idx, email_info in enumerate(emails, 1):
            print(f"\n[Email {idx}]")
            print(f"  ID: {email_info['id']}")
            print(f"  From: {email_info['from']}")
            print(f"  To: {email_info['to']}")
            print(f"  Subject: {email_info['subject']}")
            print(f"  Date: {email_info['date']}")
            print(f"  Message-ID: {email_info['message_id']}")
            
            if email_info.get('dkim_signature'):
                print(f"  DKIM-Signature: {email_info['dkim_signature'][:80]}...")
            else:
                print(f"  DKIM-Signature: None")
            
            # แสดง DMARC status
            if email_info.get('has_dmarc'):
                print(f"  DMARC: ✓ Found")
            else:
                print(f"  DMARC: ✗ Not found")
            
            if 'dkim' in email_info:
                dkim_info = email_info['dkim']
                status = "✓ VERIFIED" if dkim_info['verified'] else "✗ FAILED"
                print(f"  DKIM Status: {status}")
                if dkim_info['verified']:
                    print(f"    Domain: {dkim_info['domain']}")
                    print(f"    Selector: {dkim_info['selector']}")
                    print(f"    Algorithm: {dkim_info['algorithm']}")
                print(f"    Message: {dkim_info['message']}")
            
            print("-" * 80)
    
    def list_emails_in_folder(self, 
                              folder: str = 'dmarc-report',
                              limit: int = None,
                              days: int = None) -> List[Dict]:
        """
        แสดงรายการอีเมลในโฟลเดอร์ที่ระบุ
        
        Args:
            folder: โฟลเดอร์ที่ต้องการแสดง (default: dmarc-report)
            limit: จำกัดจำนวนอีเมลที่แสดง (None = ทั้งหมด)
            days: จำนวนวันที่ย้อนหลังที่ต้องการแสดง (None = ทั้งหมด)
            
        Returns:
            list: รายการอีเมลพร้อมข้อมูล
        """
        if not self.imap:
            self.connect()
        
        try:
            # เลือกโฟลเดอร์
            self.select_folder(folder)
        except Exception as e:
            print(f"✗ Folder '{folder}' not found or empty: {str(e)}")
            return []
        
        # สร้าง search criteria ตามวันที่
        search_criteria = self.get_date_search_criteria(days)
        
        # ค้นหาอีเมล
        status, messages = self.imap.search(None, search_criteria)
        if status != 'OK':
            print(f"✗ Failed to search emails: {messages}")
            return []
        
        email_ids = messages[0].split()
        email_ids.reverse()  # เรียงจากใหม่ไปเก่า
        
        if limit:
            email_ids = email_ids[:limit]
        
        emails = []
        
        date_info = f" (last {days} days)" if days else ""
        print(f"\n{'='*80}")
        print(f"Emails in folder: {folder}{date_info}")
        print(f"{'='*80}")
        print(f"Total emails found: {len(email_ids)}")
        
        for idx, email_id in enumerate(email_ids, 1):
            try:
                # แปลง email_id เป็น string (ถ้าเป็น bytes)
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                
                # ดึงอีเมล header
                status, msg_data = self.imap.fetch(email_id_str, '(RFC822.HEADER)')
                if status != 'OK':
                    continue
                
                header_data = msg_data[0][1]
                msg = email.message_from_bytes(header_data)
                
                # แปลงข้อมูลอีเมล
                email_info = {
                    'id': email_id_str,
                    'subject': self.decode_mime_words(msg.get('Subject', 'No Subject')),
                    'from': self.decode_mime_words(msg.get('From', 'Unknown')),
                    'to': self.decode_mime_words(msg.get('To', 'Unknown')),
                    'date': msg.get('Date', 'Unknown'),
                    'message_id': msg.get('Message-ID', 'Unknown'),
                }
                
                emails.append(email_info)
                
                # แสดงอีเมล
                print(f"\n[{idx}] ID: {email_info['id']}")
                print(f"    From: {email_info['from']}")
                print(f"    Subject: {email_info['subject'][:80]}{'...' if len(email_info['subject']) > 80 else ''}")
                print(f"    Date: {email_info['date']}")
                
            except Exception as e:
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                # ตรวจสอบว่าเป็น IMAP error หรือไม่
                if 'invalid messageset' in str(e).lower() or 'too many invalid' in str(e).lower():
                    # อีเมลอาจถูกลบหรือย้ายไปแล้ว
                    print(f"  ⚠️  Skipped email {email_id_str}: may have been moved or deleted")
                else:
                    print(f"  ✗ Error processing email {email_id_str}: {str(e)}")
                continue
        
        print(f"\n{'='*80}")
        print(f"Total displayed: {len(emails)} email(s)")
        print(f"{'='*80}")
        
        return emails
    
    def disconnect(self):
        """ปิดการเชื่อมต่อ IMAP"""
        if self.imap:
            try:
                self.imap.close()
                self.imap.logout()
                print("\n✓ Disconnected from IMAP server")
            except:
                pass
    
    def extract_attachments(self, msg: Message) -> List[Dict[str, Any]]:
        """
        ดึงไฟล์แนบจากอีเมล
        
        Args:
            msg: Email message object
            
        Returns:
            list: รายการไฟล์แนบพร้อมข้อมูล
        """
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                # ตรวจสอบว่ามี attachment หรือไม่
                content_disposition = part.get('Content-Disposition', '')
                if 'attachment' in content_disposition or 'inline' in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        # ถอดรหัส filename ที่เป็น encoded
                        decoded_filename = self.decode_mime_words(filename)
                        
                        # ดึงข้อมูล payload
                        payload = part.get_payload(decode=True)
                        if payload:
                            attachments.append({
                                'filename': decoded_filename,
                                'payload': payload,
                                'content_type': part.get_content_type(),
                                'size': len(payload)
                            })
        else:
            # ถ้าไม่ใช่ multipart แต่มี filename
            filename = msg.get_filename()
            if filename:
                decoded_filename = self.decode_mime_words(filename)
                payload = msg.get_payload(decode=True)
                if payload:
                    attachments.append({
                        'filename': decoded_filename,
                        'payload': payload,
                        'content_type': msg.get_content_type(),
                        'size': len(payload)
                    })
        
        return attachments
    
    def get_email_date(self, msg: Message) -> datetime:
        """
        ดึงวันที่จากอีเมล
        
        Args:
            msg: Email message object
            
        Returns:
            datetime: วันที่ของอีเมล (ใช้ datetime.now() ถ้าไม่พบ)
        """
        date_str = msg.get('Date')
        if date_str:
            try:
                return parsedate_to_datetime(date_str)
            except:
                pass
        
        # ถ้าไม่สามารถ parse ได้ ใช้เวลาปัจจุบัน
        return datetime.now()
    
    def sanitize_filename(self, filename: str) -> str:
        """
        ทำความสะอาดชื่อไฟล์ (ลบอักขระที่ไม่ถูกต้อง) แต่เก็บชื่อเดิมไว้
        
        Args:
            filename: ชื่อไฟล์เดิม
            
        Returns:
            str: ชื่อไฟล์ที่ทำความสะอาดแล้ว (เก็บชื่อเดิมไว้ให้มากที่สุด)
        """
        if not filename:
            return 'attachment'
        
        # ลบ whitespace ที่หัวท้าย
        filename = filename.strip()
        
        # ถ้ายังว่างเปล่า ให้ใช้ชื่อ default
        if not filename:
            return 'attachment'
        
        # ลบอักขระที่ไม่ถูกต้องสำหรับชื่อไฟล์ (เฉพาะที่จำเป็นเท่านั้น)
        # แต่เก็บชื่อเดิมไว้ เช่น "report.xml" จะยังเป็น "report.xml"
        # แค่ลบอักขระที่อาจทำให้เกิดปัญหาเท่านั้น
        # ลบเฉพาะ path separators และอักขระที่อันตรายเท่านั้น
        filename = filename.replace('/', '_').replace('\\', '_')
        filename = re.sub(r'[<>:"|?*\x00-\x1f]', '_', filename)
        
        # ตรวจสอบว่าไม่ใช่ชื่อไฟล์ว่างเปล่าหลังทำความสะอาด
        filename = filename.strip()
        if not filename:
            return 'attachment'
        
        return filename
    
    def save_attachments_by_date(self, 
                                 folder: str = 'dmarc-report',
                                 output_base_dir: str = 'dmarc-report',
                                 days: int = None,
                                 limit: int = None) -> Dict[str, Any]:
        """
        อ่านอีเมลจากโฟลเดอร์ dmarc และบันทึก attachments แยกตามวัน
        
        Args:
            folder: โฟลเดอร์ที่ต้องการอ่าน (default: dmarc)
            output_base_dir: โฟลเดอร์สำหรับบันทึก attachments (default: dmarc)
            days: จำนวนวันที่ย้อนหลัง (None = ทั้งหมด)
            limit: จำกัดจำนวนอีเมลที่ตรวจสอบ (None = ทั้งหมด)
            
        Returns:
            dict: สถิติการบันทึก attachments
        """
        if not self.imap:
            self.connect()
        
        # เลือกโฟลเดอร์
        try:
            self.select_folder(folder)
        except:
            print(f"✗ Folder '{folder}' not found or empty")
            return {
                'total_emails': 0,
                'emails_with_attachments': 0,
                'total_attachments': 0,
                'total_saved': 0,
                'total_failed': 0,
                'files': []
            }
        
        # สร้าง search criteria ตามวันที่
        search_criteria = self.get_date_search_criteria(days)
        
        # ค้นหาอีเมล
        status, messages = self.imap.search(None, search_criteria)
        if status != 'OK':
            raise Exception(f"Failed to search emails: {messages}")
        
        email_ids = messages[0].split()
        if limit:
            email_ids = email_ids[:limit]
        
        stats = {
            'total_emails': 0,
            'emails_with_attachments': 0,
            'total_attachments': 0,
            'total_saved': 0,
            'total_skipped': 0,
            'total_failed': 0,
            'files': []
        }
        
        date_info = f" (last {days} days)" if days else ""
        print(f"\nProcessing emails from '{folder}'{date_info}...")
        print(f"Found {len(email_ids)} email(s)")
        
        # สร้างโฟลเดอร์ output base ถ้ายังไม่มี
        os.makedirs(output_base_dir, exist_ok=True)
        
        for email_id in email_ids:
            try:
                stats['total_emails'] += 1
                
                # แปลง email_id เป็น string (ถ้าเป็น bytes)
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                
                # ดึงอีเมล
                status, msg_data = self.imap.fetch(email_id_str, '(RFC822)')
                if status != 'OK':
                    continue
                
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # ดึงวันที่
                email_date = self.get_email_date(msg)
                date_dir = email_date.strftime('%Y-%m-%d')
                
                # สร้างโฟลเดอร์ตามวันที่
                date_folder = os.path.join(output_base_dir, date_dir)
                os.makedirs(date_folder, exist_ok=True)
                
                # ดึง attachments
                attachments = self.extract_attachments(msg)
                
                if attachments:
                    stats['emails_with_attachments'] += 1
                    stats['total_attachments'] += len(attachments)
                    
                    subject = self.decode_mime_words(msg.get('Subject', 'No Subject'))
                    from_addr = self.decode_mime_words(msg.get('From', 'Unknown'))
                    
                    for att in attachments:
                        try:
                            # ใช้ชื่อไฟล์เดิมจากอีเมล (ทำความสะอาดเฉพาะอักขระที่ไม่ปลอดภัยเท่านั้น)
                            original_filename = att['filename']
                            clean_filename = self.sanitize_filename(original_filename)
                            
                            # สร้าง path สำหรับบันทึกไฟล์
                            file_path = os.path.join(date_folder, clean_filename)
                            
                            # ตรวจสอบว่าไฟล์ถูก extract ไปแล้วหรือยัง
                            if os.path.exists(file_path):
                                # ตรวจสอบขนาดไฟล์ว่าตรงกันหรือไม่
                                existing_size = os.path.getsize(file_path)
                                if existing_size == att['size']:
                                    # ไฟล์มีอยู่แล้วและขนาดตรงกัน ข้ามไป
                                    print(f"  ⊘ Skipped (already exists): {date_dir}/{clean_filename} ({att['size']} bytes)")
                                    stats['total_skipped'] += 1
                                    continue
                                else:
                                    # ไฟล์มีอยู่แต่ขนาดไม่ตรงกัน ให้เพิ่ม timestamp
                                    name, ext = os.path.splitext(clean_filename)
                                    timestamp = datetime.now().strftime('%H%M%S')
                                    clean_filename = f"{name}_{timestamp}{ext}"
                                    file_path = os.path.join(date_folder, clean_filename)
                            
                            # บันทึกไฟล์
                            with open(file_path, 'wb') as f:
                                f.write(att['payload'])
                            
                            stats['total_saved'] += 1
                            stats['files'].append({
                                'filename': clean_filename,
                                'original_filename': original_filename,  # เก็บชื่อเดิมไว้ด้วย
                                'path': file_path,
                                'size': att['size'],
                                'date': date_dir,
                                'subject': subject,
                                'from': from_addr
                            })
                            
                            # แสดงชื่อไฟล์เดิมด้วยถ้าต่างจากชื่อที่บันทึก
                            filename_display = clean_filename
                            if original_filename != clean_filename:
                                filename_display = f"{original_filename} -> {clean_filename}"
                            
                            print(f"  ✓ Saved: {date_dir}/{clean_filename} ({att['size']} bytes)")
                            
                        except Exception as e:
                            stats['total_failed'] += 1
                            print(f"  ✗ Failed to save {att['filename']}: {str(e)}")
                            continue
                
            except Exception as e:
                email_id_str = email_id.decode('utf-8') if isinstance(email_id, bytes) else str(email_id)
                # ตรวจสอบว่าเป็น IMAP error หรือไม่
                if 'invalid messageset' in str(e).lower() or 'too many invalid' in str(e).lower():
                    # อีเมลอาจถูกลบหรือย้ายไปแล้ว
                    print(f"  ⚠️  Skipped email {email_id_str}: may have been moved or deleted")
                else:
                    print(f"  ✗ Error processing email {email_id_str}: {str(e)}")
                stats['total_failed'] += 1
                continue
        
        return stats
    
    def extract_archives_in_directory(self, base_dir: str, skip_existing: bool = True) -> Dict[str, Any]:
        """
        Extract ไฟล์ archive (zip, gz) ทั้งหมดในโฟลเดอร์ base_dir และ subdirectories
        
        Args:
            base_dir: โฟลเดอร์ที่ต้องการ scan
            skip_existing: True = ข้ามไฟล์ที่ extract ไปแล้ว, False = extract ทุกไฟล์
            
        Returns:
            dict: สถิติการ extract
        """
        stats = {
            'total_files': 0,
            'extracted': 0,
            'skipped': 0,
            'failed': 0,
            'extracted_files': []
        }
        
        base_path = Path(base_dir)
        if not base_path.exists():
            print(f"✗ Directory not found: {base_dir}")
            return stats
        
        print(f"\nExtracting archives in: {base_dir}")
        
        # Walk through all subdirectories
        for date_dir in sorted(base_path.iterdir()):
            if not date_dir.is_dir():
                continue
            
            # Extract ไปยังโฟลเดอร์เดียวกัน (ไม่ใช่ extracted/)
            
            # Scan ไฟล์ในโฟลเดอร์วันที่
            for file_path in date_dir.iterdir():
                if not file_path.is_file():
                    continue
                
                # Skip hidden files และ XML files (ที่ extract ไปแล้ว)
                if file_path.name.startswith('.') or file_path.suffix.lower() == '.xml':
                    continue
                
                # ตรวจสอบว่าเป็น archive file หรือไม่
                if file_path.suffix.lower() not in ['.zip', '.gz']:
                    continue
                
                stats['total_files'] += 1
                
                try:
                    # ตรวจสอบว่า extract ไปแล้วหรือยัง (ถ้า skip_existing = True)
                    if skip_existing:
                        if file_path.suffix.lower() == '.gz':
                            # สำหรับ .gz ไฟล์ที่ extract จะเป็น .xml (ลบ .gz ออก)
                            expected_xml = date_dir / file_path.stem
                            if expected_xml.exists() and expected_xml.suffix.lower() == '.xml':
                                # ตรวจสอบว่าไฟล์ XML ใหม่กว่าไฟล์ .gz (แสดงว่า extract ไปแล้ว)
                                gz_mtime = file_path.stat().st_mtime
                                xml_mtime = expected_xml.stat().st_mtime
                                if xml_mtime > gz_mtime:
                                    print(f"  ⊘ Skipped (already extracted): {date_dir.name}/{file_path.name}")
                                    stats['skipped'] += 1
                                    continue
                        elif file_path.suffix.lower() == '.zip':
                            # สำหรับ .zip ตรวจสอบว่ามีไฟล์ XML อยู่ในโฟลเดอร์เดียวกันหรือยัง
                            zip_mtime = file_path.stat().st_mtime
                            xml_files = [f for f in date_dir.glob('*.xml') if f.stat().st_mtime > zip_mtime]
                            
                            if xml_files:
                                # ถ้ามี XML ไฟล์ที่ใหม่กว่า zip แสดงว่า extract ไปแล้ว
                                print(f"  ⊘ Skipped (already extracted): {date_dir.name}/{file_path.name}")
                                stats['skipped'] += 1
                                continue
                    
                    # Extract ไฟล์ไปยังโฟลเดอร์เดียวกัน
                    extracted_files = self.extract_archive(str(file_path), str(date_dir))
                    
                    if extracted_files:
                        stats['extracted'] += 1
                        stats['extracted_files'].extend(extracted_files)
                        print(f"  ✓ Extracted {len(extracted_files)} file(s) from {date_dir.name}/{file_path.name}")
                    else:
                        stats['failed'] += 1
                        print(f"  ✗ Failed to extract: {date_dir.name}/{file_path.name}")
                        
                except Exception as e:
                    stats['failed'] += 1
                    print(f"  ✗ Error extracting {date_dir.name}/{file_path.name}: {str(e)}")
                    continue
        
        return stats
    
    def extract_archive(self, file_path: str, output_dir: str) -> List[str]:
        """
        Extract ไฟล์ archive (zip, gz) ออกมาเป็น XML
        
        Args:
            file_path: path ของไฟล์ archive
            output_dir: โฟลเดอร์สำหรับ extract ไฟล์
            
        Returns:
            list: รายการ path ของไฟล์ XML ที่ extract ได้
        """
        extracted_files = []
        
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                return extracted_files
            
            # สร้างโฟลเดอร์ output
            os.makedirs(output_dir, exist_ok=True)
            
            # ตรวจสอบประเภทไฟล์
            if file_path.lower().endswith('.zip'):
                # Extract ZIP - extract ไฟล์ภายในออกมาเป็น XML ในโฟลเดอร์เดียวกัน
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    for member in zip_ref.namelist():
                        # Extract เฉพาะไฟล์ XML และ .gz
                        if member.lower().endswith('.xml') or member.lower().endswith('.gz'):
                            # สำหรับ .zip ต้อง extract โดยไม่เก็บ path structure
                            member_name = os.path.basename(member)  # ใช้ชื่อไฟล์เท่านั้น
                            
                            # Extract ไปยัง output_dir โดยใช้ชื่อไฟล์เท่านั้น
                            zip_ref.extract(member, output_dir)
                            extracted_path = os.path.join(output_dir, member)
                            
                            # ถ้า member มี path structure ให้ย้ายไปยัง output_dir โดยตรง
                            if os.path.dirname(member):
                                # ย้ายไฟล์จาก subdirectory ไปยัง output_dir
                                final_path = os.path.join(output_dir, member_name)
                                if extracted_path != final_path:
                                    if os.path.exists(extracted_path):
                                        import shutil
                                        shutil.move(extracted_path, final_path)
                                    # ลบ subdirectory ถ้าว่าง
                                    subdir = os.path.dirname(extracted_path)
                                    if subdir and os.path.exists(subdir):
                                        try:
                                            os.rmdir(subdir)
                                        except:
                                            pass
                                extracted_path = final_path
                            
                            extracted_files.append(extracted_path)
                            
                            # ถ้าเป็น .gz ให้ extract ต่อ (เป็น .xml)
                            if extracted_path.lower().endswith('.gz'):
                                gz_extracted = self.extract_archive(extracted_path, output_dir)
                                extracted_files.extend(gz_extracted)
                                # ลบไฟล์ .gz หลังจาก extract แล้ว
                                try:
                                    os.remove(extracted_path)
                                except:
                                    pass
            
            elif file_path.lower().endswith('.gz'):
                # Extract GZ - extract เป็น .xml ในโฟลเดอร์เดียวกัน
                # ตรวจสอบว่าไฟล์ที่ extract จะเป็น .xml หรือไม่
                if file_path_obj.stem.lower().endswith('.xml'):
                    # ถ้าชื่อไฟล์มี .xml อยู่แล้ว (เช่น report.xml.gz) ให้ใช้ชื่อนั้น
                    extracted_filename = file_path_obj.stem
                else:
                    # ถ้าไม่มี .xml ให้เพิ่ม .xml (เช่น report.gz -> report.xml)
                    extracted_filename = file_path_obj.stem + '.xml'
                
                extracted_path = os.path.join(output_dir, extracted_filename)
                
                # ตรวจสอบว่าไฟล์มีอยู่แล้วหรือยัง (ไม่ extract ซ้ำ)
                if not os.path.exists(extracted_path):
                    with gzip.open(file_path, 'rb') as gz_file:
                        with open(extracted_path, 'wb') as out_file:
                            out_file.write(gz_file.read())
                    
                    extracted_files.append(extracted_path)
                else:
                    # ใช้ไฟล์ที่มีอยู่แล้ว
                    extracted_files.append(extracted_path)
            
            elif file_path.lower().endswith('.xml'):
                # ถ้าเป็น XML อยู่แล้ว ให้คัดลอกไปยัง output_dir
                extracted_filename = file_path_obj.name
                extracted_path = os.path.join(output_dir, extracted_filename)
                
                import shutil
                shutil.copy2(file_path, extracted_path)
                extracted_files.append(extracted_path)
            
        except Exception as e:
            print(f"  ✗ Error extracting {file_path}: {str(e)}")
        
        return extracted_files
    
    def parse_dmarc_xml(self, xml_file_path: str) -> Dict[str, Any]:
        """
        Parse DMARC XML report และดึงข้อมูล
        
        Args:
            xml_file_path: path ของไฟล์ XML
            
        Returns:
            dict: ข้อมูลที่ parse ได้จาก DMARC report
        """
        result = {
            'report_metadata': {},
            'policy_published': {},
            'records': [],
            'summary': {
                'total_records': 0,
                'spf_pass': 0,
                'spf_fail': 0,
                'dkim_pass': 0,
                'dkim_fail': 0,
                'dmarc_pass': 0,
                'dmarc_fail': 0,
                'disposition_pass': 0,  # none/quarantine/reject
                'disposition_fail': 0
            },
            'error': None
        }
        
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            
            # ตรวจสอบ namespace จาก root element
            # DMARC XML อาจมีหรือไม่มี namespace
            if root.tag.startswith('{'):
                # มี namespace
                namespace = root.tag.split('}')[0][1:]
                ns = {'dmarc': namespace}
                prefix = 'dmarc:'
            else:
                # ไม่มี namespace
                ns = {}
                prefix = ''
            
            # Parse report_metadata
            metadata = root.find(f'.//{prefix}report_metadata', ns) if prefix else root.find('.//report_metadata')
            if metadata is not None:
                org_name = metadata.find(f'{prefix}org_name', ns) if prefix else metadata.find('org_name')
                email_elem = metadata.find(f'{prefix}email', ns) if prefix else metadata.find('email')
                extra_contact_info = metadata.find(f'{prefix}extra_contact_info', ns) if prefix else metadata.find('extra_contact_info')
                report_id = metadata.find(f'{prefix}report_id', ns) if prefix else metadata.find('report_id')
                date_range = metadata.find(f'{prefix}date_range', ns) if prefix else metadata.find('date_range')
                date_range_begin = date_range.find(f'{prefix}begin', ns) if date_range is not None and prefix else (date_range.find('begin') if date_range is not None else None)
                date_range_end = date_range.find(f'{prefix}end', ns) if date_range is not None and prefix else (date_range.find('end') if date_range is not None else None)
                
                result['report_metadata'] = {
                    'org_name': org_name.text if org_name is not None else 'Unknown',
                    'email': email_elem.text if email_elem is not None else 'Unknown',
                    'extra_contact_info': extra_contact_info.text if extra_contact_info is not None else '',
                    'report_id': report_id.text if report_id is not None else 'Unknown',
                    'date_range_begin': int(date_range_begin.text) if date_range_begin is not None and date_range_begin.text else 0,
                    'date_range_end': int(date_range_end.text) if date_range_end is not None and date_range_end.text else 0
                }
            
            # Parse policy_published
            policy = root.find(f'.//{prefix}policy_published', ns) if prefix else root.find('.//policy_published')
            if policy is not None:
                domain = policy.find(f'{prefix}domain', ns) if prefix else policy.find('domain')
                adkim = policy.find(f'{prefix}adkim', ns) if prefix else policy.find('adkim')
                aspf = policy.find(f'{prefix}aspf', ns) if prefix else policy.find('aspf')
                p = policy.find(f'{prefix}p', ns) if prefix else policy.find('p')
                sp = policy.find(f'{prefix}sp', ns) if prefix else policy.find('sp')
                pct = policy.find(f'{prefix}pct', ns) if prefix else policy.find('pct')
                
                result['policy_published'] = {
                    'domain': domain.text if domain is not None else 'Unknown',
                    'adkim': adkim.text if adkim is not None else 'r',
                    'aspf': aspf.text if aspf is not None else 'r',
                    'p': p.text if p is not None else 'none',
                    'sp': sp.text if sp is not None else 'none',
                    'pct': int(pct.text) if pct is not None and pct.text else 100
                }
            
            # Parse records
            records = root.findall(f'.//{prefix}record', ns) if prefix else root.findall('.//record')
            result['summary']['total_records'] = len(records)
            
            for record in records:
                record_data = {}
                
                # Row data
                row = record.find(f'{prefix}row', ns) if prefix else record.find('row')
                if row is not None:
                    source_ip = row.find(f'{prefix}source_ip', ns) if prefix else row.find('source_ip')
                    count = row.find(f'{prefix}count', ns) if prefix else row.find('count')
                    policy_evaluated = row.find(f'{prefix}policy_evaluated', ns) if prefix else row.find('policy_evaluated')
                    
                    disposition = (policy_evaluated.find(f'{prefix}disposition', ns) if prefix else policy_evaluated.find('disposition')) if policy_evaluated is not None else None
                    dkim_result = (policy_evaluated.find(f'{prefix}dkim', ns) if prefix else policy_evaluated.find('dkim')) if policy_evaluated is not None else None
                    spf_result = (policy_evaluated.find(f'{prefix}spf', ns) if prefix else policy_evaluated.find('spf')) if policy_evaluated is not None else None
                    
                    record_data['row'] = {
                        'source_ip': source_ip.text if source_ip is not None else 'Unknown',
                        'count': int(count.text) if count is not None else 0,
                        'disposition': disposition.text if disposition is not None else 'none',
                        'dkim_result': dkim_result.text if dkim_result is not None else 'none',
                        'spf_result': spf_result.text if spf_result is not None else 'none'
                    }
                    
                    # สรุปผล
                    count_value = int(count.text) if count is not None else 0
                    
                    if spf_result is not None:
                        if spf_result.text == 'pass':
                            result['summary']['spf_pass'] += count_value
                        else:
                            result['summary']['spf_fail'] += count_value
                    
                    if dkim_result is not None:
                        if dkim_result.text == 'pass':
                            result['summary']['dkim_pass'] += count_value
                        else:
                            result['summary']['dkim_fail'] += count_value
                    
                    # Disposition: none = pass, quarantine/reject = fail
                    if disposition is not None:
                        if disposition.text == 'none':
                            result['summary']['disposition_pass'] += count_value
                        else:
                            result['summary']['disposition_fail'] += count_value
                    
                    # DMARC pass/fail: ใช้ disposition เป็นหลัก (none = pass, quarantine/reject = fail)
                    # แต่ถ้าไม่มี disposition ให้ดูจาก SPF หรือ DKIM pass
                    if disposition is not None:
                        # ถ้ามี disposition ให้ใช้ disposition เป็นหลัก
                        if disposition.text == 'none':
                            result['summary']['dmarc_pass'] += count_value
                        else:
                            result['summary']['dmarc_fail'] += count_value
                    else:
                        # ถ้าไม่มี disposition ให้ดูจาก SPF หรือ DKIM pass
                        # DMARC pass ถ้า SPF หรือ DKIM pass (alignment ผ่าน)
                        if (spf_result is not None and spf_result.text == 'pass') or \
                           (dkim_result is not None and dkim_result.text == 'pass'):
                            result['summary']['dmarc_pass'] += count_value
                        else:
                            result['summary']['dmarc_fail'] += count_value
                
                # Identifiers
                identifiers = record.find(f'{prefix}identifiers', ns) if prefix else record.find('identifiers')
                if identifiers is not None:
                    header_from = identifiers.find(f'{prefix}header_from', ns) if prefix else identifiers.find('header_from')
                    record_data['identifiers'] = {
                        'header_from': header_from.text if header_from is not None else 'Unknown'
                    }
                
                # Auth results
                auth_results = record.find(f'{prefix}auth_results', ns) if prefix else record.find('auth_results')
                if auth_results is not None:
                    dkim_auth = auth_results.find(f'{prefix}dkim', ns) if prefix else auth_results.find('dkim')
                    spf_auth = auth_results.find(f'{prefix}spf', ns) if prefix else auth_results.find('spf')
                    
                    dkim_domain = None
                    dkim_result_text = None
                    if dkim_auth is not None:
                        dkim_domain_elem = dkim_auth.find(f'{prefix}domain', ns) if prefix else dkim_auth.find('domain')
                        dkim_result_elem = dkim_auth.find(f'{prefix}result', ns) if prefix else dkim_auth.find('result')
                        dkim_domain = dkim_domain_elem.text if dkim_domain_elem is not None else None
                        dkim_result_text = dkim_result_elem.text if dkim_result_elem is not None else None
                    
                    spf_domain = None
                    spf_result_text = None
                    if spf_auth is not None:
                        spf_domain_elem = spf_auth.find(f'{prefix}domain', ns) if prefix else spf_auth.find('domain')
                        spf_result_elem = spf_auth.find(f'{prefix}result', ns) if prefix else spf_auth.find('result')
                        spf_domain = spf_domain_elem.text if spf_domain_elem is not None else None
                        spf_result_text = spf_result_elem.text if spf_result_elem is not None else None
                    
                    record_data['auth_results'] = {
                        'dkim': {
                            'domain': dkim_domain,
                            'result': dkim_result_text
                        } if dkim_auth is not None else None,
                        'spf': {
                            'domain': spf_domain,
                            'result': spf_result_text
                        } if spf_auth is not None else None
                    }
                
                result['records'].append(record_data)
        
        except Exception as e:
            result['error'] = str(e)
            print(f"  ✗ Error parsing XML {xml_file_path}: {str(e)}")
        
        return result
    
    def process_dmarc_files(self, base_dir: str, extract: bool = True) -> Dict[str, Any]:
        """
        Process ไฟล์ DMARC (extract และ parse XML)
        
        Args:
            base_dir: โฟลเดอร์ที่มีไฟล์ DMARC
            extract: True = extract ไฟล์ zip/gz, False = parse XML เท่านั้น
            
        Returns:
            dict: สรุปผลการตรวจสอบ DMARC
        """
        summary = {
            'total_files': 0,
            'processed': 0,
            'failed': 0,
            'xml_files': [],
            'reports': []
        }
        
        base_path = Path(base_dir)
        if not base_path.exists():
            print(f"✗ Directory not found: {base_dir}")
            return summary
        
        print(f"\nProcessing DMARC files in: {base_dir}")
        
        # Walk through all subdirectories
        for date_dir in sorted(base_path.iterdir()):
            if not date_dir.is_dir():
                continue
            
            print(f"\nProcessing date: {date_dir.name}")
            # Extract ไปยังโฟลเดอร์เดียวกัน (ไม่ใช่ extracted/)
            
            for file_path in date_dir.iterdir():
                if file_path.is_file():
                    summary['total_files'] += 1
                    
                    # Skip hidden files เท่านั้น (ไม่ skip XML เพราะต้อง parse)
                    if file_path.name.startswith('.'):
                        continue
                    
                    try:
                        # Extract ถ้าต้องการ
                        xml_files = []
                        if extract and (file_path.suffix.lower() in ['.zip', '.gz']):
                            xml_files = self.extract_archive(str(file_path), str(date_dir))
                            if xml_files:
                                print(f"  ✓ Extracted {len(xml_files)} file(s) from {file_path.name}")
                        elif file_path.suffix.lower() == '.xml':
                            # ถ้าเป็น XML อยู่แล้ว ให้ parse โดยตรง
                            xml_files = [str(file_path)]
                        else:
                            # Skip ไฟล์อื่นๆ ที่ไม่ใช่ zip, gz, หรือ xml
                            continue
                        
                        # Parse XML files
                        for xml_file in xml_files:
                            xml_path = Path(xml_file)
                            if xml_path.suffix.lower() != '.xml':
                                continue
                            
                            # ตรวจสอบว่าไฟล์มีอยู่จริง
                            if not xml_path.exists():
                                continue
                            
                            print(f"  Parsing: {xml_path.name}")
                            parsed = self.parse_dmarc_xml(str(xml_path))
                            
                            if parsed['error'] is None:
                                summary['processed'] += 1
                                summary['xml_files'].append(str(xml_path))
                                summary['reports'].append({
                                    'file': str(xml_path),
                                    'date': date_dir.name,
                                    'report_id': parsed['report_metadata'].get('report_id', 'Unknown'),
                                    'domain': parsed['policy_published'].get('domain', 'Unknown'),
                                    'date_range_begin': parsed['report_metadata'].get('date_range_begin', 0),
                                    'date_range_end': parsed['report_metadata'].get('date_range_end', 0),
                                    'summary': parsed['summary']
                                })
                            else:
                                summary['failed'] += 1
                                print(f"  ✗ Error parsing {xml_path.name}: {parsed['error']}")
                    
                    except Exception as e:
                        print(f"  ✗ Error processing {file_path.name}: {str(e)}")
                        summary['failed'] += 1
                        continue
        
        return summary
    
    def print_dmarc_summary(self, summary: Dict[str, Any]):
        """
        แสดงสรุปผลการตรวจสอบ DMARC
        
        Args:
            summary: ผลการ process DMARC files
        """
        print(f"\n{'='*80}")
        print("DMARC Report Summary")
        print(f"{'='*80}")
        print(f"Total files found: {summary['total_files']}")
        print(f"Successfully processed: {summary['processed']}")
        print(f"Failed: {summary['failed']}")
        
        if summary['reports']:
            print(f"\n{'='*80}")
            print("Reports Summary:")
            print(f"{'='*80}")
            
            # รวมสรุปทั้งหมด
            total_summary = {
                'total_records': 0,
                'spf_pass': 0,
                'spf_fail': 0,
                'dkim_pass': 0,
                'dkim_fail': 0,
                'dmarc_pass': 0,
                'dmarc_fail': 0,
                'disposition_pass': 0,
                'disposition_fail': 0
            }
            
            for report in summary['reports']:
                rep_summary = report['summary']
                total_summary['total_records'] += rep_summary['total_records']
                total_summary['spf_pass'] += rep_summary['spf_pass']
                total_summary['spf_fail'] += rep_summary['spf_fail']
                total_summary['dkim_pass'] += rep_summary['dkim_pass']
                total_summary['dkim_fail'] += rep_summary['dkim_fail']
                total_summary['dmarc_pass'] += rep_summary['dmarc_pass']
                total_summary['dmarc_fail'] += rep_summary['dmarc_fail']
                total_summary['disposition_pass'] += rep_summary['disposition_pass']
                total_summary['disposition_fail'] += rep_summary['disposition_fail']
            
            print(f"\nOverall Statistics:")
            print(f"  Total Records: {total_summary['total_records']:,}")
            
            total_spf = total_summary['spf_pass'] + total_summary['spf_fail']
            total_dkim = total_summary['dkim_pass'] + total_summary['dkim_fail']
            total_dmarc = total_summary['dmarc_pass'] + total_summary['dmarc_fail']
            
            print(f"\n  SPF:")
            if total_spf > 0:
                print(f"    Pass: {total_summary['spf_pass']:,} ({total_summary['spf_pass']/total_spf*100:.1f}%)")
                print(f"    Fail: {total_summary['spf_fail']:,} ({total_summary['spf_fail']/total_spf*100:.1f}%)")
            else:
                print(f"    Pass: 0")
                print(f"    Fail: 0")
            
            print(f"\n  DKIM:")
            if total_dkim > 0:
                print(f"    Pass: {total_summary['dkim_pass']:,} ({total_summary['dkim_pass']/total_dkim*100:.1f}%)")
                print(f"    Fail: {total_summary['dkim_fail']:,} ({total_summary['dkim_fail']/total_dkim*100:.1f}%)")
            else:
                print(f"    Pass: 0")
                print(f"    Fail: 0")
            
            print(f"\n  DMARC:")
            if total_dmarc > 0:
                print(f"    Pass: {total_summary['dmarc_pass']:,} ({total_summary['dmarc_pass']/total_dmarc*100:.1f}%)")
                print(f"    Fail: {total_summary['dmarc_fail']:,} ({total_summary['dmarc_fail']/total_dmarc*100:.1f}%)")
            else:
                print(f"    Pass: 0")
                print(f"    Fail: 0")
            
            print(f"\n  Disposition:")
            print(f"    Pass (none): {total_summary['disposition_pass']:,}")
            print(f"    Fail (quarantine/reject): {total_summary['disposition_fail']:,}")
            
            # แสดงรายละเอียดแต่ละ report
            print(f"\n{'='*80}")
            print("Individual Reports:")
            print(f"{'='*80}")
            
            for report in summary['reports']:
                domain = report['domain']
                report_id = report['report_id']
                date_range_begin = datetime.fromtimestamp(report['date_range_begin'])
                date_range_end = datetime.fromtimestamp(report['date_range_end'])
                rep_summary = report['summary']
                
                print(f"\n  Report ID: {report_id}")
                print(f"  Domain: {domain}")
                print(f"  Date Range: {date_range_begin.strftime('%Y-%m-%d')} to {date_range_end.strftime('%Y-%m-%d')}")
                print(f"  Records: {rep_summary['total_records']:,}")
                print(f"    SPF: Pass={rep_summary['spf_pass']:,}, Fail={rep_summary['spf_fail']:,}")
                print(f"    DKIM: Pass={rep_summary['dkim_pass']:,}, Fail={rep_summary['dkim_fail']:,}")
                print(f"    DMARC: Pass={rep_summary['dmarc_pass']:,}, Fail={rep_summary['dmarc_fail']:,}")


def main():
    """ฟังก์ชันหลักสำหรับทดสอบ"""
    import argparse
    
    parser = argparse.ArgumentParser(description='IMAP DKIM/DMARC Email Reader')
    parser.add_argument('--move-dmarc', action='store_true', 
                       help='Move emails with DMARC to dmarc folder')
    parser.add_argument('--extract-attachments', action='store_true',
                       help='Extract attachments from dmarc folder emails and save by date')
    parser.add_argument('--process-dmarc', action='store_true',
                       help='Process DMARC XML files (extract and parse)')
    parser.add_argument('--list-emails', action='store_true',
                       help='List emails in dmarc-report folder')
    parser.add_argument('--source-folder', default='INBOX',
                       help='Source folder to scan (default: INBOX)')
    parser.add_argument('--target-folder', default='dmarc-report',
                       help='Target folder for DMARC emails (default: dmarc-report)')
    parser.add_argument('--output-dir', default='dmarc-report',
                       help='Output directory for saving attachments (default: dmarc-report)')
    parser.add_argument('--limit', type=int, default=None,
                       help='Limit number of emails to check')
    parser.add_argument('--days', type=int, default=None,
                       help='Scan emails from the last N days only (e.g., 7 for last 7 days)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be moved without actually moving')
    
    args = parser.parse_args()
    
    # อ่านค่าจาก environment variables หรือใช้ค่า default
    IMAP_SERVER = os.getenv('IMAP_SERVER', 'imap.gmail.com')
    IMAP_PORT = int(os.getenv('IMAP_PORT', '993'))
    IMAP_USERNAME = os.getenv('IMAP_USERNAME')
    IMAP_PASSWORD = os.getenv('IMAP_PASSWORD')
    
    if not IMAP_USERNAME or not IMAP_PASSWORD:
        print("Error: Please set IMAP_USERNAME and IMAP_PASSWORD in .env file or environment variables")
        print("\nExample .env file:")
        print("IMAP_SERVER=imap.gmail.com")
        print("IMAP_PORT=993")
        print("IMAP_USERNAME=your-email@gmail.com")
        print("IMAP_PASSWORD=your-app-password")
        return
    
    # สร้าง reader
    reader = IMAPDKIMReader(
        imap_server=IMAP_SERVER,
        imap_port=IMAP_PORT,
        username=IMAP_USERNAME,
        password=IMAP_PASSWORD
    )
    
    try:
        if args.process_dmarc:
            # โหมด process DMARC files (extract และ parse XML)
            # ไม่ต้องเชื่อมต่อ IMAP เพราะ process files ที่ local
            print(f"\n{'='*80}")
            print("DMARC XML Processor")
            print(f"{'='*80}")
            print(f"Processing directory: {args.output_dir}")
            print()
            
            # Process DMARC files
            summary = reader.process_dmarc_files(args.output_dir, extract=True)
            
            # แสดงสรุปผล
            reader.print_dmarc_summary(summary)
        
        else:
            # โหมดอื่นๆ ต้องเชื่อมต่อ IMAP
            reader.connect()
            
            if args.move_dmarc:
                # โหมดย้ายอีเมล DMARC
                print(f"\n{'='*80}")
                print("DMARC Email Mover")
                print(f"{'='*80}")
                if args.dry_run:
                    print("⚠️  DRY RUN MODE - No emails will be moved")
                print(f"Source folder: {args.source_folder}")
                print(f"Target folder: {args.target_folder}")
                if args.days:
                    print(f"Scan period: Last {args.days} days")
                if args.limit:
                    print(f"Limit: {args.limit} emails")
                print()
                
                stats = reader.move_dmarc_emails(
                    source_folder=args.source_folder,
                    target_folder=args.target_folder,
                    limit=args.limit,
                    days=args.days,
                    dry_run=args.dry_run
                )
                
                # แสดงผลลัพธ์
                print(f"\n{'='*80}")
                print("Summary:")
                print(f"{'='*80}")
                print(f"Total emails checked: {stats['total_checked']}")
                print(f"DMARC emails found: {stats['dmarc_found']}")
                if args.dry_run:
                    print(f"Would move: {stats['moved']} emails")
                else:
                    print(f"Successfully moved: {stats['moved']} emails")
                    print(f"Failed to move: {stats['failed']} emails")
                
                if stats['emails']:
                    print(f"\nDMARC emails:")
                    for email_info in stats['emails']:
                        print(f"  - {email_info['subject'][:60]}")
                        print(f"    From: {email_info['from']}")
            
            elif args.extract_attachments:
                # โหมดดึง attachments จากโฟลเดอร์ dmarc
                # ใช้ source_folder เป็น dmarc ถ้าไม่ได้ระบุ
                source_folder = args.source_folder if args.source_folder != 'INBOX' else 'dmarc-report'
                
                print(f"\n{'='*80}")
                print("DMARC Attachment Extractor")
                print(f"{'='*80}")
                print(f"Source folder: {source_folder}")
                print(f"Output directory: {args.output_dir}")
                if args.days:
                    print(f"Scan period: Last {args.days} days")
                if args.limit:
                    print(f"Limit: {args.limit} emails")
                print()
                
                stats = reader.save_attachments_by_date(
                    folder=source_folder,
                    output_base_dir=args.output_dir,
                    days=args.days,
                    limit=args.limit
                )
                
                # แสดงผลลัพธ์
                print(f"\n{'='*80}")
                print("Summary:")
                print(f"{'='*80}")
                print(f"Total emails processed: {stats['total_emails']}")
                print(f"Emails with attachments: {stats['emails_with_attachments']}")
                print(f"Total attachments found: {stats['total_attachments']}")
                print(f"Successfully saved: {stats['total_saved']}")
                print(f"Skipped (already exists): {stats['total_skipped']}")
                print(f"Failed to save: {stats['total_failed']}")
                
                if stats['files']:
                    print(f"\nSaved files:")
                    # จัดกลุ่มตามวันที่
                    files_by_date = {}
                    for file_info in stats['files']:
                        date = file_info['date']
                        if date not in files_by_date:
                            files_by_date[date] = []
                        files_by_date[date].append(file_info)
                    
                    for date in sorted(files_by_date.keys(), reverse=True):
                        print(f"\n  {date}:")
                        for file_info in files_by_date[date]:
                            size_kb = file_info['size'] / 1024
                            print(f"    - {file_info['filename']} ({size_kb:.2f} KB)")
                
                # Extract archives อัตโนมัติหลังจาก save attachments
                print(f"\n{'='*80}")
                print("Extracting archives...")
                print(f"{'='*80}")
                extract_stats = reader.extract_archives_in_directory(
                    base_dir=args.output_dir,
                    skip_existing=True
                )
                
                print(f"\nExtraction Summary:")
                print(f"  Total archive files found: {extract_stats['total_files']}")
                print(f"  Successfully extracted: {extract_stats['extracted']}")
                print(f"  Skipped (already extracted): {extract_stats['skipped']}")
                print(f"  Failed: {extract_stats['failed']}")
                print(f"  Total XML files extracted: {len(extract_stats['extracted_files'])}")
            
            elif args.list_emails:
                # โหมดแสดงรายการอีเมลในโฟลเดอร์ dmarc-report
                folder = args.target_folder if args.target_folder else 'dmarc-report'
                
                print(f"\n{'='*80}")
                print("DMARC Report Email Lister")
                print(f"{'='*80}")
                print(f"Folder: {folder}")
                if args.days:
                    print(f"Period: Last {args.days} days")
                if args.limit:
                    print(f"Limit: {args.limit} emails")
                print()
                
                emails = reader.list_emails_in_folder(
                    folder=folder,
                    limit=args.limit,
                    days=args.days
                )
            
            else:
                # โหมดปกติ: แสดงอีเมล
                # แสดงรายการโฟลเดอร์
                print("\nAvailable folders:")
                folders = reader.list_folders()
                for folder in folders[:10]:  # แสดง 10 โฟลเดอร์แรก
                    print(f"  - {folder}")
                
                # อ่านอีเมลจาก INBOX
                date_info = f" (last {args.days} days)" if args.days else ""
                print(f"\nFetching emails from INBOX{date_info}...")
                emails = reader.fetch_emails(folder='INBOX', limit=5, verify_dkim=True, days=args.days)
                
                # แสดงอีเมล
                reader.display_emails(emails)
        
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # ปิดการเชื่อมต่อ IMAP เฉพาะถ้าเชื่อมต่อแล้ว
        if args.process_dmarc is False and reader.imap:
            reader.disconnect()


if __name__ == '__main__':
    main()

