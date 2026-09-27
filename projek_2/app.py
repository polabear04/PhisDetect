from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import pickle
import numpy as np
import mysql.connector
import json
import os
from feature_extractor import ekstrak_fitur
from urllib.parse import urlparse
import ipaddress
import socket

app = Flask(__name__)
CORS(app)

try:
    model = pickle.load(open('model_skripsi_final.pkl', 'rb'))
    print("Sistem AI Skripsi berhasil dimuat ke server!")
except Exception as e:
    print(f"Error memuat model: {e}")
    model = None

FILE_WHITELIST = 'whitelist.json'

def muat_whitelist():
    if os.path.exists(FILE_WHITELIST):
        with open(FILE_WHITELIST, 'r') as f:
            return json.load(f)
    return []

def simpan_whitelist(data):
    with open(FILE_WHITELIST, 'w') as f:
        json.dump(data, f)

whitelist_global = muat_whitelist()

def susun_alasan_pemblokiran(fitur_list, url):
    alasan = []
    if len(fitur_list) >= 12:
        if fitur_list[5] == 1: alasan.append("Menggunakan IP Address langsung sebagai domain (menyembunyikan identitas asli).")
        if fitur_list[0] > 75: alasan.append(f"Ukuran URL terlalu panjang ({fitur_list[0]} karakter), berpotensi menyembunyikan nama asli website.")
        if fitur_list[6] == 1: alasan.append("Mengandung kata kunci manipulatif (seperti login, verify, secure, atau bank).")
        if fitur_list[7] > 3.8: alasan.append("Tingkat keacakan nama domain sangat tinggi (indikasi DGA).")
        if fitur_list[8] > 0.15: alasan.append(f"Proporsi penggunaan angka di dalam URL tidak wajar ({round(fitur_list[8]*100)}%).")
        if fitur_list[11] == 1: alasan.append("Mendeteksi token 'https' palsu di dalam nama domain.")
        
    if len(fitur_list) == 13 and fitur_list[12] == 1:
        alasan.append("PERINGATAN TYPOSQUATTING: Nama domain memplesetkan situs web populer.")

    if not alasan:
        alasan.append("Kombinasi struktur pola URL terindikasi kuat sebagai serangan phishing oleh algoritma Random Forest.")
        
    return alasan

def url_aman_untuk_di_fetch(url):
    try:
        host = urlparse(url).hostname
        if not host:
            return False
        ip = socket.gethostbyname(host)
        alamat = ipaddress.ip_address(ip)
        if alamat.is_private or alamat.is_loopback or alamat.is_link_local or alamat.is_reserved:
            return False
        return True
    except Exception:
        return False

def analisis_konten_web(url):
    kata_kunci_phishing = ['login', 'password', 'verify', 'urgent', 'suspend', 'update account', 'bank', 'secure', 'wallet']
    alasan_tambahan = []

    if not url_aman_untuk_di_fetch(url):
        return False, []

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=3)
        
        if response.status_code != 200:
            return False, []
            
        soup = BeautifulSoup(response.text, 'html.parser')
        teks_halaman = soup.get_text().lower()

        kata_ditemukan = [kata for kata in kata_kunci_phishing if kata in teks_halaman]
        
        if len(kata_ditemukan) >= 3:
            alasan_tambahan.append(f"Analisis Konten (NLP): Ditemukan indikasi rekayasa sosial ({', '.join(kata_ditemukan)}).")
            return True, alasan_tambahan
            
    except requests.exceptions.Timeout:
        return False, []
    except Exception as e:
        return False, []
        
    return False, []

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url_input = data.get('url', '')
    if not url_input:
        return jsonify({'error': 'URL tidak ditemukan'}), 400

    if url_input in whitelist_global:
        return jsonify({'url': url_input, 'status': 'AMAN', 'confidence': 100.0, 'reasons': ['URL ini berada di dalam daftar putih (Whitelist) aman pengguna.']})

    try:
        fitur_list = ekstrak_fitur(url_input)
        fitur_array = np.array([fitur_list])
    except Exception as e:
        return jsonify({'error': f'Gagal mengekstrak fitur URL: {str(e)}'}), 500
    
    if model is None:
        return jsonify({'error': 'Model AI belum dimuat ke server.'}), 500

    hasil = int(model.predict(fitur_array)[0]) 
    
    try:
        prob_array = model.predict_proba(fitur_array)[0]
        probabilitas = float(prob_array[hasil]) if len(prob_array) > 1 else (1.0 if hasil == 1 else 1.0)
    except Exception:
        probabilitas = 1.0
        
    persentase = round(probabilitas * 100, 2)
    status = "PHISHING" if hasil == 1 else "AMAN"
    alasan_blokir = []
    pelanggaran_manual = susun_alasan_pemblokiran(fitur_list, url_input)
    pelanggaran_manual = [a for a in pelanggaran_manual if "Kombinasi struktur" not in a]

    if status == "PHISHING":
        alasan_blokir = susun_alasan_pemblokiran(fitur_list, url_input)
    else:
        domain_asli = urlparse(url_input).netloc.lower()
        if not domain_asli: 
            domain_asli = url_input.lower()
        kata_kunci_bahaya = ['login', 'verify', 'secure', 'update', 'account', 'bank', 'wallet', 'service', 'support', 'bca', 'bri']
        kata_ditemukan = [kw for kw in kata_kunci_bahaya if kw in domain_asli]
        
        if len(fitur_list) >= 12 and fitur_list[5] == 1:
            status = "PHISHING"
            persentase = 95.0
            alasan_blokir = ["PELANGGARAN FATAL: Penggunaan IP Address langsung sebagai domain."]
        elif len(kata_ditemukan) >= 2: 
            status = "PHISHING"
            persentase = 88.0
            alasan_blokir = [f"PELANGGARAN HEURISTIK: Domain mengandung pola kata rekayasa sosial ({', '.join(kata_ditemukan)})."]
            alasan_blokir.extend([f"Catatan: {p}" for p in pelanggaran_manual])
        else:
            alasan_blokir.extend([f"Catatan: {p}" for p in pelanggaran_manual])

    is_phishing_content, alasan_nlp = analisis_konten_web(url_input)
    
    if is_phishing_content:
        alasan_blokir.extend(alasan_nlp)
        if status == "AMAN" and persentase < 65.0:
            status = "PHISHING"
            persentase = 80.0
            alasan_blokir.insert(0, "AI merasa ragu, dan NLP memastikan adanya konten manipulatif.")

    if not alasan_blokir and status == "AMAN":
        alasan_blokir.append("Tidak ditemukan pola mencurigakan pada struktur leksikal URL.")

    print(f"Hasil Analisis Akhir: {url_input} -> {status} ({persentase}%)")
    
    mydb, mycursor = None, None
    try:
        mydb = mysql.connector.connect(host="localhost", user="root", password="", database="db_phishing")
        mycursor = mydb.cursor()
        sql = "INSERT INTO scan_history (url, status, confidence, reasons) VALUES (%s, %s, %s, %s)"
        val = (url_input, status, float(persentase), json.dumps(alasan_blokir))
        mycursor.execute(sql, val)
        mydb.commit()
    except mysql.connector.Error as err:
        print("Error DB MySQL:", err)
    finally:
        if mycursor: mycursor.close()
        if mydb and mydb.is_connected(): mydb.close()
    
    return jsonify({'url': url_input, 'status': status, 'confidence': persentase, 'reasons': alasan_blokir})

@app.route('/report', methods=['POST'])
def report_error():
    data = request.json
    url, original_status = data.get('url'), data.get('original_status')
    reported_as = "AMAN" if original_status == "PHISHING" else "PHISHING"
    mydb, mycursor = None, None
    try:
        mydb = mysql.connector.connect(host="localhost", user="root", password="", database="db_phishing")
        mycursor = mydb.cursor()
        sql = "INSERT INTO reported_urls (url, original_status, reported_as) VALUES (%s, %s, %s)"
        mycursor.execute(sql, (url, original_status, reported_as))
        mydb.commit()
        return jsonify({"sukses": True, "pesan": "Laporan disimpan."})
    except mysql.connector.Error as err:
        return jsonify({"sukses": False, "error": str(err)}), 500
    finally:
        if mycursor: mycursor.close()
        if mydb and mydb.is_connected(): mydb.close()

@app.route('/api/stats', methods=['GET'])
def get_stats():
    mydb, mycursor = None, None
    try:
        mydb = mysql.connector.connect(host="localhost", user="root", password="", database="db_phishing")
        mycursor = mydb.cursor(dictionary=True)
        mycursor.execute("SELECT COUNT(*) as total FROM scan_history")
        total_scans = mycursor.fetchone()['total']
        mycursor.execute("SELECT status, COUNT(*) as count FROM scan_history GROUP BY status")
        status_counts = mycursor.fetchall()
        phishing_count = sum([r['count'] for r in status_counts if r['status'] == 'PHISHING'])
        aman_count = sum([r['count'] for r in status_counts if r['status'] == 'AMAN'])
        mycursor.execute("SELECT url, status, confidence, DATE_FORMAT(scan_date, '%d-%m-%Y %H:%i') as scan_date FROM scan_history ORDER BY id DESC LIMIT 5")
        recent_scans = mycursor.fetchall()
        mycursor.execute("SELECT COUNT(*) as total_reports FROM reported_urls")
        total_reports = mycursor.fetchone()['total_reports']
        return jsonify({"total_scans": total_scans, "phishing_count": phishing_count, "aman_count": aman_count, "recent_scans": recent_scans, "total_reports": total_reports})
    except mysql.connector.Error as err:
        return jsonify({"total_scans": 0, "phishing_count": 0, "aman_count": 0, "recent_scans": [], "total_reports": 0, "error": str(err)})
    finally:
        if mycursor: mycursor.close()
        if mydb and mydb.is_connected(): mydb.close()
            
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)