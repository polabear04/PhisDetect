import re
import math
from urllib.parse import urlparse
from difflib import SequenceMatcher

def hitung_entropy(teks):
    if not teks:
        return 0
    probabilitas = [float(teks.count(c)) / len(teks) for c in dict.fromkeys(list(teks))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in probabilitas])
    return entropy

def ekstrak_fitur(url):
    fitur = []
    url = str(url)
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    # 1. Panjang URL
    fitur.append(len(url))
    # 2. Jumlah Titik '.'
    fitur.append(url.count('.'))
    # 3. Jumlah Hyphen/Strip '-'
    fitur.append(url.count('-'))
    # 4. Kehadiran Simbol '@' (1=Ada, 0=Tidak)
    fitur.append(1 if '@' in url else 0)
    # 5. Jumlah Garis Miring '/'
    fitur.append(url.count('/'))
    
    # 6. Deteksi IP Address
    ip_pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5]))')
    fitur.append(1 if ip_pattern.search(url) else 0)
    
    # 7. Deteksi Keyword Sensitif (Phishing)
    url_lower = url.lower()
    keyword_match = 1 if re.search(r'(login|verify|secure|update|bank|account|paypal|admin|free)', url_lower) else 0
    fitur.append(keyword_match)

    # 8. Entropy URL (Tingkat Keacakan)
    fitur.append(hitung_entropy(domain))

    # 9. Rasio Angka dan Huruf
    jumlah_angka = sum(c.isdigit() for c in url)
    rasio_angka = jumlah_angka / len(url) if len(url) > 0 else 0
    fitur.append(rasio_angka)

    # 10. Kehadiran Karakter Spesial Ekstrem ('=', '?', '_', '%')
    jumlah_spesial = sum(url.count(c) for c in ['=', '?', '_', '%'])
    fitur.append(jumlah_spesial)

    # 11. Panjang Nama Domain Saja
    fitur.append(len(domain))

    # 12. Token 'HTTPS' Palsu di dalam Nama Domain
    fitur.append(1 if 'https' in domain else 0)

    # --- INOVASI: 13. Deteksi Typosquatting (Domain Plesetan) ---
    target_populer = ["google.com", "facebook.com", "klikbca.com", "paypal.com", "instagram.com", "whatsapp.com"]
    is_typosquatting = 0
    
    for target in target_populer:
        # Menghitung rasio kemiripan (0.0 sampai 1.0)
        kemiripan = SequenceMatcher(None, domain.lower(), target).ratio()
        # Jika kemiripan di atas 80% tapi tidak 100% persis sama, itu indikasi kuat Typosquatting!
        if 0.80 < kemiripan < 1.0:
            is_typosquatting = 1
            break
            
    fitur.append(is_typosquatting)

    # Pastikan total mutlak ada 13 nilai yang dikembalikan
    return fitur