#!/usr/bin/env python3
"""
DMARC Report Dashboard
Web dashboard สำหรับดู DMARC reports
"""

from flask import Flask, render_template, jsonify
from pathlib import Path
import os
from datetime import datetime
import json
import sys
from io import StringIO

app = Flask(__name__)

# โฟลเดอร์สำหรับเก็บ DMARC reports
DMARC_DIR = os.getenv('DMARC_DIR', 'dmarc-report')

# Import IMAPDKIMReader แบบ lazy เพื่อไม่ให้ต้องมี IMAP credentials เมื่อรัน dashboard
try:
    from imap_dkim_reader import IMAPDKIMReader
except ImportError:
    IMAPDKIMReader = None


def process_dmarc_silently(reader, base_dir: str, extract: bool = True):
    """
    Process DMARC files โดยไม่แสดง print output (redirect stdout)
    """
    # Redirect stdout เพื่อไม่ให้ print ข้อความออกมา
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    
    try:
        summary = reader.process_dmarc_files(base_dir, extract=extract)
        return summary
    finally:
        # Restore stdout
        sys.stdout = old_stdout


@app.route('/')
def index():
    """หน้า dashboard หลัก"""
    return render_template('dashboard.html')


@app.route('/api/reports')
def get_reports():
    """API สำหรับดึงรายการ reports"""
    try:
        if IMAPDKIMReader is None:
            return jsonify({'error': 'IMAPDKIMReader not available'}), 500
        
        reader = IMAPDKIMReader()
        
        # Process DMARC files (silently to avoid print output)
        summary = process_dmarc_silently(reader, DMARC_DIR, extract=True)
        
        # ตรวจสอบว่า summary มี structure ที่ถูกต้อง
        if not isinstance(summary, dict):
            return jsonify({'error': 'Invalid summary format', 'summary_type': str(type(summary))}), 500
        
        if 'reports' not in summary:
            summary['reports'] = []
        
        # แปลง timestamp เป็น readable format
        for report in summary.get('reports', []):
            if 'date_range_begin' in report and report['date_range_begin'] > 0:
                report['date_range_begin_str'] = datetime.fromtimestamp(
                    report['date_range_begin']
                ).strftime('%Y-%m-%d %H:%M:%S')
            else:
                report['date_range_begin_str'] = 'Unknown'
            
            if 'date_range_end' in report and report['date_range_end'] > 0:
                report['date_range_end_str'] = datetime.fromtimestamp(
                    report['date_range_end']
                ).strftime('%Y-%m-%d %H:%M:%S')
            else:
                report['date_range_end_str'] = 'Unknown'
        
        return jsonify(summary)
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        print(f"Error in get_reports: {error_msg}")
        print(traceback_str)
        return jsonify({
            'error': 'Failed to get reports',
            'message': error_msg,
            'traceback': traceback_str if app.debug else None
        }), 500


@app.route('/api/summary')
def get_summary():
    """API สำหรับดึงสรุปผลรวม"""
    try:
        if IMAPDKIMReader is None:
            return jsonify({'error': 'IMAPDKIMReader not available'}), 500
        
        reader = IMAPDKIMReader()
        summary = process_dmarc_silently(reader, DMARC_DIR, extract=True)
        
        # ตรวจสอบว่า summary มี structure ที่ถูกต้อง
        if not isinstance(summary, dict):
            return jsonify({'error': 'Invalid summary format', 'summary_type': str(type(summary))}), 500
        
        # รวมสรุปทั้งหมด
        total_summary = {
            'total_files': summary.get('total_files', 0),
            'processed': summary.get('processed', 0),
            'failed': summary.get('failed', 0),
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
        
        for report in summary.get('reports', []):
            if 'summary' not in report:
                print(f"Warning: Report missing 'summary' field: {report.get('report_id', 'Unknown')}")
                continue
            rep_summary = report['summary']
            if not isinstance(rep_summary, dict):
                print(f"Warning: Report summary is not a dict: {type(rep_summary)}")
                continue
            
            # รวมข้อมูลจากแต่ละ report
            total_summary['total_records'] += rep_summary.get('total_records', 0)
            total_summary['spf_pass'] += rep_summary.get('spf_pass', 0)
            total_summary['spf_fail'] += rep_summary.get('spf_fail', 0)
            total_summary['dkim_pass'] += rep_summary.get('dkim_pass', 0)
            total_summary['dkim_fail'] += rep_summary.get('dkim_fail', 0)
            total_summary['dmarc_pass'] += rep_summary.get('dmarc_pass', 0)
            total_summary['dmarc_fail'] += rep_summary.get('dmarc_fail', 0)
            total_summary['disposition_pass'] += rep_summary.get('disposition_pass', 0)
            total_summary['disposition_fail'] += rep_summary.get('disposition_fail', 0)
        
        # คำนวณเปอร์เซ็นต์
        total_spf = total_summary['spf_pass'] + total_summary['spf_fail']
        total_dkim = total_summary['dkim_pass'] + total_summary['dkim_fail']
        total_dmarc = total_summary['dmarc_pass'] + total_summary['dmarc_fail']
        total_disposition = total_summary['disposition_pass'] + total_summary['disposition_fail']
        
        total_summary['spf_pass_pct'] = round(
            (total_summary['spf_pass'] / total_spf * 100) if total_spf > 0 else 0, 2
        )
        total_summary['dkim_pass_pct'] = round(
            (total_summary['dkim_pass'] / total_dkim * 100) if total_dkim > 0 else 0, 2
        )
        total_summary['dmarc_pass_pct'] = round(
            (total_summary['dmarc_pass'] / total_dmarc * 100) if total_dmarc > 0 else 0, 2
        )
        total_summary['disposition_pass_pct'] = round(
            (total_summary['disposition_pass'] / total_disposition * 100) if total_disposition > 0 else 0, 2
        )
        
        # Debug: ตรวจสอบความถูกต้องของข้อมูล
        if app.debug:
            print(f"Summary totals: records={total_summary['total_records']}, "
                  f"SPF={total_spf}, DKIM={total_dkim}, DMARC={total_dmarc}, "
                  f"Disposition={total_disposition}")
        
        return jsonify(total_summary)
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        print(f"Error in get_summary: {error_msg}")
        print(traceback_str)
        return jsonify({
            'error': 'Failed to get summary',
            'message': error_msg,
            'traceback': traceback_str if app.debug else None
        }), 500


@app.route('/api/domains')
def get_domains():
    """API สำหรับดึงรายการ domains"""
    try:
        if IMAPDKIMReader is None:
            return jsonify({'error': 'IMAPDKIMReader not available'}), 500
        
        reader = IMAPDKIMReader()
        summary = process_dmarc_silently(reader, DMARC_DIR, extract=True)
        
        # ตรวจสอบว่า summary มี structure ที่ถูกต้อง
        if not isinstance(summary, dict):
            return jsonify({'error': 'Invalid summary format', 'summary_type': str(type(summary))}), 500
        
        # จัดกลุ่มตาม domain
        domains = {}
        for report in summary.get('reports', []):
            if 'domain' not in report or 'summary' not in report:
                continue
            domain = report['domain']
            if domain not in domains:
                domains[domain] = {
                    'domain': domain,
                    'total_reports': 0,
                    'total_records': 0,
                    'spf_pass': 0,
                    'spf_fail': 0,
                    'dkim_pass': 0,
                    'dkim_fail': 0,
                    'dmarc_pass': 0,
                    'dmarc_fail': 0
                }
            
            domains[domain]['total_reports'] += 1
            rep_summary = report['summary']
            domains[domain]['total_records'] += rep_summary.get('total_records', 0)
            domains[domain]['spf_pass'] += rep_summary.get('spf_pass', 0)
            domains[domain]['spf_fail'] += rep_summary.get('spf_fail', 0)
            domains[domain]['dkim_pass'] += rep_summary.get('dkim_pass', 0)
            domains[domain]['dkim_fail'] += rep_summary.get('dkim_fail', 0)
            domains[domain]['dmarc_pass'] += rep_summary.get('dmarc_pass', 0)
            domains[domain]['dmarc_fail'] += rep_summary.get('dmarc_fail', 0)
        
        return jsonify(list(domains.values()))
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        print(f"Error in get_domains: {error_msg}")
        print(traceback_str)
        return jsonify({
            'error': 'Failed to get domains',
            'message': error_msg,
            'traceback': traceback_str if app.debug else None
        }), 500


@app.route('/api/trends')
def get_trends():
    """API สำหรับดึงข้อมูลแนวโน้ม 7 วันย้อนหลัง"""
    try:
        if IMAPDKIMReader is None:
            return jsonify({'error': 'IMAPDKIMReader not available'}), 500
        
        reader = IMAPDKIMReader()
        summary = process_dmarc_silently(reader, DMARC_DIR, extract=True)
        
        # ตรวจสอบว่า summary มี structure ที่ถูกต้อง
        if not isinstance(summary, dict):
            return jsonify({'error': 'Invalid summary format', 'summary_type': str(type(summary))}), 500
        
        # คำนวณวันที่ 7 วันย้อนหลัง
        from datetime import datetime, timedelta
        today = datetime.now()
        trends = []
        
        for i in range(6, -1, -1):  # 7 วันย้อนหลัง (6, 5, 4, 3, 2, 1, 0)
            date = today - timedelta(days=i)
            date_str = date.strftime('%Y-%m-%d')
            
            # รวมข้อมูลจาก reports ที่อยู่ในวันนั้น
            day_summary = {
                'date': date_str,
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
            
            for report in summary.get('reports', []):
                # ตรวจสอบว่า report อยู่ในช่วงวันที่นี้หรือไม่
                if 'date_range_begin' in report and 'date_range_end' in report:
                    report_begin = datetime.fromtimestamp(report['date_range_begin'])
                    report_end = datetime.fromtimestamp(report['date_range_end'])
                    
                    # ตรวจสอบว่า date อยู่ในช่วง report หรือไม่
                    if report_begin.date() <= date.date() <= report_end.date():
                        if 'summary' in report:
                            rep_summary = report['summary']
                            day_summary['total_records'] += rep_summary.get('total_records', 0)
                            day_summary['spf_pass'] += rep_summary.get('spf_pass', 0)
                            day_summary['spf_fail'] += rep_summary.get('spf_fail', 0)
                            day_summary['dkim_pass'] += rep_summary.get('dkim_pass', 0)
                            day_summary['dkim_fail'] += rep_summary.get('dkim_fail', 0)
                            day_summary['dmarc_pass'] += rep_summary.get('dmarc_pass', 0)
                            day_summary['dmarc_fail'] += rep_summary.get('dmarc_fail', 0)
                            day_summary['disposition_pass'] += rep_summary.get('disposition_pass', 0)
                            day_summary['disposition_fail'] += rep_summary.get('disposition_fail', 0)
            
            # คำนวณเปอร์เซ็นต์
            total_spf = day_summary['spf_pass'] + day_summary['spf_fail']
            total_dkim = day_summary['dkim_pass'] + day_summary['dkim_fail']
            total_dmarc = day_summary['dmarc_pass'] + day_summary['dmarc_fail']
            
            day_summary['spf_pass_pct'] = round(
                (day_summary['spf_pass'] / total_spf * 100) if total_spf > 0 else 0, 2
            )
            day_summary['dkim_pass_pct'] = round(
                (day_summary['dkim_pass'] / total_dkim * 100) if total_dkim > 0 else 0, 2
            )
            day_summary['dmarc_pass_pct'] = round(
                (day_summary['dmarc_pass'] / total_dmarc * 100) if total_dmarc > 0 else 0, 2
            )
            
            trends.append(day_summary)
        
        return jsonify({'trends': trends})
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        print(f"Error in get_trends: {error_msg}")
        print(traceback_str)
        return jsonify({
            'error': 'Failed to get trends',
            'message': error_msg,
            'traceback': traceback_str if app.debug else None
        }), 500


@app.route('/api/xml/<path:file_path>')
def get_xml_file(file_path):
    """API สำหรับดึง raw XML file"""
    try:
        # Security: ตรวจสอบว่า path ไม่มี directory traversal
        if '..' in file_path or file_path.startswith('/'):
            return jsonify({'error': 'Invalid file path'}), 400
        
        # สร้าง full path
        full_path = Path(DMARC_DIR) / file_path
        
        # ตรวจสอบว่าไฟล์อยู่ใน DMARC_DIR เท่านั้น (ป้องกัน directory traversal)
        try:
            full_path_resolved = full_path.resolve()
            dmarc_dir_resolved = Path(DMARC_DIR).resolve()
            if not str(full_path_resolved).startswith(str(dmarc_dir_resolved)):
                return jsonify({'error': 'Access denied'}), 403
        except Exception as e:
            return jsonify({'error': 'Invalid path', 'message': str(e)}), 400
        
        # ตรวจสอบว่าไฟล์มีอยู่จริง
        if not full_path.exists():
            return jsonify({'error': 'File not found', 'path': str(full_path)}), 404
        
        # ตรวจสอบว่าเป็นไฟล์ XML
        if not full_path.suffix.lower() == '.xml':
            return jsonify({'error': 'Not an XML file'}), 400
        
        # อ่านไฟล์ XML
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                xml_content = f.read()
        except UnicodeDecodeError:
            # ถ้า decode ไม่ได้ ลองใช้ latin-1
            with open(full_path, 'r', encoding='latin-1', errors='ignore') as f:
                xml_content = f.read()
        
        # Return XML content
        from flask import Response
        return Response(
            xml_content,
            mimetype='application/xml; charset=utf-8',
            headers={
                'Content-Disposition': f'inline; filename={full_path.name}'
            }
        )
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        print(f"Error in get_xml_file: {error_msg}")
        print(traceback_str)
        return jsonify({
            'error': 'Failed to get XML file',
            'message': error_msg,
            'traceback': traceback_str if app.debug else None
        }), 500


@app.route('/api/reports/<report_id>')
def get_report_detail(report_id):
    """API สำหรับดึงรายละเอียด report เดียว"""
    try:
        if IMAPDKIMReader is None:
            return jsonify({'error': 'IMAPDKIMReader not available'}), 500
        
        reader = IMAPDKIMReader()
        summary = process_dmarc_silently(reader, DMARC_DIR, extract=True)
        
        # ตรวจสอบว่า summary มี structure ที่ถูกต้อง
        if not isinstance(summary, dict):
            return jsonify({'error': 'Invalid summary format', 'summary_type': str(type(summary))}), 500
        
        # หา report ที่ตรงกับ report_id
        for report in summary.get('reports', []):
            if report.get('report_id') == report_id:
                # Parse XML file อีกครั้งเพื่อดึงรายละเอียดเต็ม
                if 'file' in report:
                    xml_file = Path(report['file'])
                    if xml_file.exists():
                        parsed = reader.parse_dmarc_xml(str(xml_file))
                        if parsed.get('error') is None:
                            return jsonify({
                                'report': report,
                                'details': parsed
                            })
        
        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        import traceback
        error_msg = str(e)
        traceback_str = traceback.format_exc()
        print(f"Error in get_report_detail: {error_msg}")
        print(traceback_str)
        return jsonify({
            'error': 'Failed to get report detail',
            'message': error_msg,
            'traceback': traceback_str if app.debug else None
        }), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    print(f"\n{'='*80}")
    print("📧 DMARC Report Dashboard")
    print(f"{'='*80}")
    print(f"🌐 Starting server on http://0.0.0.0:{port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"📁 DMARC directory: {DMARC_DIR}")
    print(f"{'='*80}")
    print(f"\n✨ Open your browser and navigate to: http://localhost:{port}")
    print(f"💡 Press CTRL+C to stop the server\n")
    app.run(debug=debug, host='0.0.0.0', port=port)



