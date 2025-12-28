# 🔒 Desa-Secure 2025

**Dashboard Audit Risiko OSINT untuk Ekosistem Digital Desa Indonesia**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red)
![License](https://img.shields.io/badge/License-Open%20Source-green)
![Status](https://img.shields.io/badge/Status-Aktif-success)

---

## 📖 Gambaran Umum

**Desa-Secure 2025** adalah alat audit OSINT (Open-Source Intelligence) yang dirancang untuk menilai risiko keamanan vendor Sistem Informasi Desa (SID) di Indonesia. 

Tool ini fokus pada domain `.desa.id` dengan analisis:
- Informasi domain
- Sertifikat SSL/TLS  
- Pemindaian port
- Header keamanan

### 🎯 Tujuan Proyek

Proyek akademik untuk mata kuliah **Audit Teknologi & Sistem Informasi**, Semester 5, 2025.

Menyediakan alat sederhana untuk administrator desa dan auditor IT dalam menilai postur keamanan vendor infrastruktur digital mereka.

---

## ✨ Fitur Utama

### 🌐 Modul Audit Domain
- Pencarian WHOIS (Registrar, tanggal pembuatan, kadaluarsa)
- Resolusi DNS ke alamat IP
- Informasi Name Server

### 🔐 Modul Audit Keamanan
- Validasi Sertifikat SSL/TLS
- Pemindai Port (HTTP, HTTPS, SSH, FTP, MySQL, PostgreSQL)
- Analisis Header Keamanan (X-Frame-Options, CSP, HSTS, dll)

### 📊 Penilaian Risiko
- Skor Risiko Otomatis
- Sistem Nilai A sampai F
- Klasifikasi: Rendah, Sedang, Menengah, Tinggi, Kritis
- Rekomendasi keamanan actionable

### 📈 Visualisasi
- Grafik Gauge Interaktif (Plotly)
- Dashboard Metrik Real-time
- Tabel Ringkasan
- Ekspor CSV dan TXT

---

## 🛠️ Teknologi

- **Python 3.8+** - Bahasa pemrograman
- **Streamlit** - Framework dashboard
- **Pandas** - Analisis data
- **Plotly** - Visualisasi interaktif
- **Python-Whois** - Data WHOIS
- **Requests** - HTTP requests
- **Socket & SSL** - Operasi jaringan

---

## 🚀 Instalasi

### Prasyarat
- Python 3.8+
- pip
- Koneksi internet

### Clone dari GitHub

```bash
git clone https://github.com/Kurnia2810/desa-secure-2025.git
cd desa-secure-2025
pip install -r requirements.txt
python -m streamlit run app.py
```

### Atau Langsung (File Sudah Ada)

```bash
cd "path/to/desa-secure-2025"
pip install -r requirements.txt
python -m streamlit run app.py
```

### Virtual Environment (Opsional)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Aplikasi akan terbuka di browser: `http://localhost:8501`

---

## 📚 Cara Penggunaan

1. Jalankan: `python -m streamlit run app.py`
2. Masukkan domain `.desa.id` (contoh: `example.desa.id`)
3. Klik "🔍 Start Audit"
4. Analisis hasil audit
5. Download laporan CSV/TXT

### Contoh Domain
- `demo.desa.id`
- `test.desa.id`  
- Domain yang Anda miliki izin audit

---

## 📊 Sistem Penilaian Risiko

| Nilai | Skor | Tingkat | Deskripsi |
|-------|------|---------|-----------|
| **A** | 90-100 | Rendah | Sangat aman |
| **B** | 80-89 | Sedang | Baik, perlu perbaikan minor |
| **C** | 70-79 | Menengah | Perlu perhatian |
| **D** | 60-69 | Tinggi | Masalah signifikan |
| **F** | 0-59 | Kritis | Kerentanan parah |

### Kriteria Penilaian

**1. Sertifikat SSL (30 poin)**
- SSL valid 90+ hari: 30 poin
- SSL valid 30-90 hari: 20 poin
- SSL valid <30 hari: 10 poin
- Tidak ada SSL: 0 poin

**2. Kadaluarsa Domain (20 poin)**
- Kadaluarsa 365+ hari: 20 poin
- Kadaluarsa 90-365 hari: 15 poin
- Kadaluarsa 30-90 hari: 10 poin
- Kadaluarsa <30 hari: 5 poin

**3. Keamanan Port (25 poin)**
- Tidak ada port sensitif: 25 poin
- 1 port sensitif: 15 poin
- 2+ port sensitif: 5 poin

**4. Header Keamanan (25 poin)**
- Implementasi 80%+: 20+ poin
- Implementasi 40-80%: 10-20 poin
- Implementasi <40%: 0-10 poin

---

## 🔍 Detail Fitur

### Tab Domain
- Nama registrar
- Tanggal pembuatan dan kadaluarsa
- Alamat IP
- Name servers

### Tab SSL/TLS
- Status validitas
- Hari hingga kadaluarsa
- Penerbit sertifikat

### Tab Port Scan
- Port: 80, 443, 22, 21, 3306, 5432, 8080, 8443
- Identifikasi layanan
- Klasifikasi risiko
- Alert port sensitif

### Tab Security Headers
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- Content-Security-Policy
- X-XSS-Protection

---

## 📦 Struktur Proyek

```
desa-secure-2025/
├── app.py              # Aplikasi utama
├── requirements.txt    # Dependencies
├── README.md          # Dokumentasi
├── .gitignore         # Git ignore
└── LICENSE            # Lisensi MIT
```

---

## 🔒 Keamanan & Hukum

### ⚠️ Disclaimer

**Tool ini HANYA untuk audit yang diotorisasi.**

- Audit hanya domain yang Anda miliki/izinkan
- Pemindaian tanpa izin mungkin ilegal
- Untuk pendidikan dan penelitian
- Patuhi hukum setempat
- Developer tidak bertanggung jawab atas penyalahgunaan

### Panduan Etis

1. **Otorisasi** - Dapatkan izin tertulis
2. **Responsible Disclosure** - Laporkan temuan dengan bijak
3. **No Harm** - Jangan merusak sistem
4. **Pendidikan** - Tingkatkan kesadaran keamanan
5. **Kepatuhan** - Ikuti UU Keamanan Siber Indonesia

---

## 🤝 Kontribusi

Proyek open-source untuk keamanan digital desa Indonesia!

### Cara Kontribusi

1. Fork repository
2. Buat branch: `git checkout -b feature/FiturBaru`
3. Commit: `git commit -m 'Tambah FiturBaru'`
4. Push: `git push origin feature/FiturBaru`
5. Buat Pull Request

### Ide Kontribusi
- Pemeriksaan DNS security
- Audit terjadwal
- Batch scanning
- Export PDF/JSON
- Multi-language
- Machine learning risk prediction

---

## 🐛 Bug Report

Gunakan GitHub Issues dengan info:
- OS dan versi Python
- Pesan error lengkap
- Langkah reproduksi
- Expected vs actual behavior

---

## 📄 Lisensi

Open source - **MIT License**

Copyright (c) 2025 Desa-Secure 2025 Contributors

---

## 👨‍💻 Penulis

**Proyek:** Desa-Secure 2025  
**Mata Kuliah:** Audit Teknologi & Sistem Informasi  
**Semester:** 5 - 2025  
**Fokus:** Keamanan Digital Desa Indonesia

### Terima Kasih
- Administrator desa Indonesia
- Komunitas open-source
- Penasihat akademik
- Kontributor proyek

---

## 📞 Kontak

- **GitHub:** [Kurnia2810/desa-secure-2025](https://github.com/Kurnia2810/desa-secure-2025)
- **Issues:** [Report Bug](https://github.com/Kurnia2810/desa-secure-2025/issues)
- **Focus:** Ekosistem Digital Desa Indonesia

---

## 🗺️ Roadmap

### ✅ Versi 1.0 (Current)
- Audit domain dasar
- Pemeriksaan SSL/TLS
- Pemindaian port
- Analisis header keamanan
- Sistem penilaian risiko
- Dashboard interaktif
- Ekspor CSV/TXT

### 🔄 Versi 2.0 (Planned)
- Batch domain scanning
- Scheduled audits
- Historical tracking
- Email notifications
- REST API
- Mobile responsive

### 🔮 Versi 3.0 (Future)
- ML-based risk prediction
- Threat intelligence integration
- Advanced vulnerability scanning
- Compliance reporting (ISO 27001)
- Multi-language support

---

## 📖 Referensi

### Ekosistem Desa
- [Sistem Informasi Desa](https://sid.kemendesa.go.id/)
- [Kementerian Desa PDTT](https://kemendesa.go.id/)

### Standar Keamanan
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls](https://www.cisecurity.org/controls)
- [NIST Framework](https://www.nist.gov/cyberframework)

### Dokumentasi
- [Streamlit Docs](https://docs.streamlit.io/)
- [Python Security](https://python.readthedocs.io/en/stable/library/security_warnings.html)

---

## 💡 FAQ

**Q: Boleh untuk komersial?**  
A: Ya, MIT License. Tapi pastikan ada izin audit.

**Q: Apakah mengubah target?**  
A: Tidak, hanya passive reconnaissance.

**Q: Data disimpan dimana?**  
A: Tidak disimpan, real-time saja.

**Q: Tambah port lain?**  
A: Ya, edit `ports_to_check` di `scan_common_ports()`.

**Q: Kenapa hanya .desa.id?**  
A: Fokus SID Indonesia. Bisa dimodifikasi untuk domain lain.

---

## 🎓 Untuk Pendidikan

Tool ini cocok untuk:
- Audit sistem informasi
- Cybersecurity training
- Penetration testing (authorized)
- OSINT techniques
- Python security programming
- Streamlit development

---

<div align="center">

### 🔒 Dibuat dengan ❤️ untuk Keamanan Digital Desa Indonesia

**Desa-Secure 2025** | Membuat Ekosistem Digital Desa Lebih Aman

⭐ **[Star repo ini](https://github.com/Kurnia2810/desa-secure-2025)** jika berguna!

</div>
