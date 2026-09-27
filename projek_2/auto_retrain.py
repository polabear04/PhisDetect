import pandas as pd
import mysql.connector
from sklearn.ensemble import RandomForestClassifier
import pickle
import numpy as np
import os
from feature_extractor import ekstrak_fitur

print("=== MEMULAI SIKLUS CONTINUOUS LEARNING PHISDETECT ===")

try:
    mydb = mysql.connector.connect(host="localhost", user="root", password="", database="db_phishing")
    query = "SELECT url, reported_as FROM reported_urls"
    df_baru = pd.read_sql(query, mydb)
    mydb.close()

    if len(df_baru) == 0:
        print("Tidak ada laporan baru di Database. Retraining dibatalkan.")
        exit()

    print(f"Ditemukan {len(df_baru)} data laporan baru dari pengguna.")
except Exception as e:
    print("Gagal terhubung ke Database:", e)
    exit()

# 2. Ekstrak 13 Fitur untuk data baru
print("Mengekstrak fitur untuk data laporan baru...")
X_baru = np.array([ekstrak_fitur(url) for url in df_baru['url']])
y_baru = df_baru['reported_as'].map({'AMAN': 0, 'PHISHING': 1}).values

FILE_DATA_ASLI = 'training_data_asli.npz'

if os.path.exists(FILE_DATA_ASLI):
    print("Menggabungkan data training asli dengan data laporan baru...")
    data_asli = np.load(FILE_DATA_ASLI)
    X_train_asli, y_train_asli = data_asli['X_train'], data_asli['y_train']

    X_gabungan = np.vstack([X_train_asli, X_baru])
    y_gabungan = np.concatenate([y_train_asli, y_baru])
    print(f"  Data asli: {len(y_train_asli)} baris | Data laporan baru: {len(y_baru)} baris "
          f"| Total gabungan: {len(y_gabungan)} baris")
else:
    print("PERINGATAN: 'training_data_asli.npz' tidak ditemukan.")
    print("Retraining akan HANYA memakai data laporan baru (model berisiko 'lupa' pola lama).")
    print("Jalankan ulang train_model.py versi terbaru agar file ini tersedia di masa depan.")
    X_gabungan, y_gabungan = X_baru, y_baru

print("Melatih ulang model dengan data gabungan (lama + baru)...")
try:
    model_baru = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model_baru.fit(X_gabungan, y_gabungan)

    with open('model_skripsi_final.pkl', 'wb') as f:
        pickle.dump(model_baru, f)

    np.savez_compressed(FILE_DATA_ASLI, X_train=X_gabungan, y_train=y_gabungan)

    print(f"✅ Retraining Berhasil! Model dilatih ulang dari {len(y_gabungan)} baris data "
          f"({len(df_baru)} di antaranya laporan baru dari pengguna).")

except Exception as e:
    print("Gagal melakukan retraining:", e)
