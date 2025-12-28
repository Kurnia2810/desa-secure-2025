# 🔒 Desa-Secure 2025

**Dashboard Audit Risiko OSINT untuk Ekosistem Digital Desa Indonesia**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-red)
![License](https://img.shields.io/badge/License-Open%20Source-green)
![Status](https://img.shields.io/badge/Status-Aktif-success)

---

## 📖 Gambaran Umum

**Desa-Secure 2025** adalah alat audit OSINT (Open-Source Intelligence) komprehensif yang dirancang khusus untuk menilai risiko keamanan vendor Sistem Informasi Desa (SID) di Indonesia. Tool ini berfokus pada domain yang berakhiran `.desa.id` dan menyediakan analisis keamanan mendalam termasuk informasi domain, sertifikat SSL/TLS, pemindaian port, dan evaluasi header keamanan.

### 🎯 Tujuan Proyek

Proyek ini dikembangkan sebagai bagian dari inisiatif akademik untuk mata kuliah **Audit Teknologi & Sistem Informasi**, Semester 5, 2025. Tujuannya adalah menyediakan administrator desa dan auditor IT dengan alat yang sederhana namun powerful untuk menilai postur keamanan vendor infrastruktur digital mereka.

---

## ✨ Fitur Utama

### 🌐 Modul Audit Domain
- **Pencarian WHOIS**: Mengambil informasi registrar, tanggal pembuatan, dan tanggal kadaluarsa
- **Resolusi DNS**: Mengonversi nama domain menjadi alamat IP
- **Informasi Name Server**: Menampilkan name server otoritatif

### 🔐 Modul Audit Keamanan
- **Validasi Sertifikat SSL/TLS**: Memeriksa validitas sertifikat, tanggal kadaluarsa, dan penerbit
- **Pemindai Port**: Pemindaian pasif port umum (HTTP, HTTPS, SSH, FTP, MySQL, PostgreSQL)
- **Analisis Header Keamanan**: Memeriksa header keamanan kritis seperti X-Frame-Options, CSP, HSTS, dll.

### 📊 Penilaian Risiko
- **Skor Risiko Cerdas**: Kalkulasi otomatis berdasarkan berbagai faktor keamanan
- **Sistem Nilai**: Skala penilaian A hingga F untuk pemahaman mudah
- **Klasifikasi Tingkat Risiko**: Kategori risiko Rendah, Sedang, Menengah, Tinggi, dan Kritis
- **Temuan Terperinci**: Rekomendasi keamanan yang jelas dan actionable

### 📈 Visualisasi
- **Grafik Gauge Interaktif**: Representasi visual skor risiko menggunakan Plotly
- **Dashboard Metrik**: Tampilan real-time indikator keamanan kunci
- **Tabel Ringkasan**: Hasil audit komprehensif dalam format tabel
- **Opsi Ekspor**: Unduh laporan dalam format CSV dan TXT

---

## 🛠️ Teknologi yang Digunakan

- **Python 3.8+**: Bahasa pemrograman inti
- **Streamlit**: Framework dashboard web interaktif
- **Pandas**: Manipulasi dan analisis data
- **Plotly**: Visualisasi data interaktif
- **Python-Whois**: Pengambilan data WHOIS
- **Requests**: HTTP request untuk analisis header
- **Socket & SSL**: Modul Python native untuk operasi jaringan

---

## 🚀 Instalasi & Pengaturan

### Prasyarat
- Python 3.8 atau lebih tinggi
- pip (Python package manager)
- Koneksi internet untuk instalasi package

### Opsi 1: Penggunaan Langsung (Tanpa Clone)

Jika Anda sudah memiliki file proyek ini di komputer Anda:

```bash
# Buka folder proyek
cd "path/to/desa-secure-2025"

# Install dependencies
pip install -r requirements.txt

# Jalankan aplikasi
streamlit run app.py
```

### Opsi 2: Clone dari GitHub

Jika repository sudah tersedia di GitHub:

```bash
# Clone repository (ganti YOUR_USERNAME dengan username GitHub Anda)
git clone https://github.com/YOUR_USERNAME/desa-secure-2025.git
cd desa-secure-2025

# Install dependencies
pip install -r requirements.txt

# Jalankan aplikasi
streamlit run app.py
```

### Virtual Environment (Opsional tapi Direkomendasikan)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Kemudian install dependencies
pip install -r requirements.txt
```

Aplikasi akan otomatis terbuka di browser default Anda pada `http://localhost:8501`

---

## 📚 Panduan Penggunaan

### Penggunaan Dasar

1. **Jalankan Aplikasi**: Eksekusi `streamlit run app.py`
2. **Masukkan Domain Target**: Input domain `.desa.id` di kolom teks (contoh: `example.desa.id`)
3. **Mulai Audit**: Klik tombol "🔍 Start Audit"
4. **Tinjau Hasil**: Analisis skor risiko, temuan, dan laporan terperinci
5. **Ekspor Laporan**: Unduh laporan CSV atau TXT untuk dokumentasi

### Contoh Domain untuk Diuji
- `demo.desa.id`
- `test.desa.id`
- Domain `.desa.id` sah yang Anda miliki otorisasi untuk audit

### Memahami Skor Risiko

| Nilai | Rentang Skor | Tingkat Risiko | Deskripsi |
|-------|--------------|----------------|-----------|
| **A** | 90-100 | Risiko Rendah | Postur keamanan sangat baik |
| **B** | 80-89 | Risiko Sedang | Keamanan baik dengan perbaikan minor diperlukan |
| **C** | 70-79 | Risiko Menengah | Keamanan memadai tapi perlu perhatian |
| **D** | 60-69 | Risiko Tinggi | Masalah keamanan signifikan ditemukan |
| **F** | 0-59 | Risiko Kritis | Kerentanan keamanan parah |

### Kriteria Penilaian Risiko

Skor risiko dihitung berdasarkan empat faktor utama:

1. **Sertifikat SSL (30 poin)**
   - SSL valid dengan 90+ hari: 30 poin
   - SSL valid dengan 30-90 hari: 20 poin
   - SSL valid dengan <30 hari: 10 poin
   - Tidak ada/SSL tidak valid: 0 poin

2. **Kadaluarsa Domain (20 poin)**
   - Kadaluarsa dalam 365+ hari: 20 poin
   - Kadaluarsa dalam 90-365 hari: 15 poin
   - Kadaluarsa dalam 30-90 hari: 10 poin
   - Kadaluarsa dalam <30 hari: 5 poin

3. **Keamanan Port (25 poin)**
   - Tidak ada port sensitif terbuka: 25 poin
   - 1 port sensitif terbuka: 15 poin
   - 2+ port sensitif terbuka: 5 poin

4. **Header Keamanan (25 poin)**
   - Berdasarkan persentase implementasi header
   - Implementasi 80%+: 20+ poin
   - Implementasi 40-80%: 10-20 poin
   - Implementasi <40%: 0-10 poin

---

## 🔍 Fitur Secara Detail

### Tab Informasi Domain
Menampilkan data registrasi domain komprehensif:
- Nama registrar
- Tanggal pembuatan domain
- Tanggal kadaluarsa domain
- Alamat IP saat ini
- Name server

### Tab SSL/TLS
Menganalisis keamanan sertifikat SSL:
- Status validitas sertifikat
- Hari hingga kadaluarsa
- Penerbit sertifikat
- Tanggal kadaluarsa

### Tab Pemindaian Port
Menampilkan port terbuka dan tingkat risikonya:
- Port yang diperiksa: 80, 443, 22, 21, 3306, 5432, 8080, 8443
- Identifikasi layanan
- Klasifikasi risiko untuk setiap port terbuka
- Peringatan untuk port sensitif (MySQL, PostgreSQL, FTP, SSH)

### Tab Header Keamanan
Mengevaluasi header keamanan HTTP:
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- Content-Security-Policy
- X-XSS-Protection

---

## 🎨 Antarmuka Pengguna

Dashboard menampilkan desain modern dan intuitif dengan:
- **Sidebar**: Informasi proyek, tech stack, dan bagian tentang
- **Header Utama**: Branding dan judul proyek
- **Bagian Input**: Kolom entri domain dan tombol trigger audit
- **Bagian Hasil**: Diatur dalam beberapa tab untuk navigasi mudah
- **Bagian Ekspor**: Akses cepat untuk mengunduh laporan

---

## 📦 Struktur Proyek

```
desa-secure-2025/
│
├── app.py                  # Aplikasi Streamlit utama
├── requirements.txt        # Dependencies Python
├── README.md              # File ini
├── .gitignore             # Aturan Git ignore
└── LICENSE                # Lisensi open source
```

---

## 🔒 Pertimbangan Keamanan & Hukum

### Disclaimer Penting

⚠️ **Alat ini dirancang khusus untuk tujuan audit keamanan yang diotorisasi.**

- Hanya audit domain yang Anda miliki atau memiliki izin tertulis eksplisit untuk menguji
- Pemindaian port tanpa otorisasi mungkin ilegal di beberapa yurisdiksi
- Alat ini untuk tujuan pendidikan dan penelitian
- Selalu patuhi hukum dan regulasi lokal
- Developer tidak bertanggung jawab atas penyalahgunaan alat ini

### Panduan Penggunaan Etis

1. **Otorisasi**: Selalu dapatkan izin sebelum mengaudit domain apa pun
2. **Pengungkapan Bertanggung Jawab**: Laporkan temuan kepada pemilik domain secara bertanggung jawab
3. **Tidak Membahayakan**: Jangan gunakan alat ini untuk merugikan, mengganggu, atau mengeksploitasi sistem
4. **Tujuan Pendidikan**: Gunakan untuk pembelajaran dan meningkatkan kesadaran keamanan
5. **Kepatuhan**: Pastikan kepatuhan terhadap undang-undang keamanan siber Indonesia

---

## 🤝 Kontribusi

Kontribusi sangat diterima! Ini adalah proyek open-source yang bertujuan meningkatkan keamanan digital desa di Indonesia.

### Cara Berkontribusi

1. Fork repository
2. Buat branch fitur (`git checkout -b feature/FiturKeren`)
3. Commit perubahan Anda (`git commit -m 'Menambahkan FiturKeren'`)
4. Push ke branch (`git push origin feature/FiturKeren`)
5. Buka Pull Request

### Ide Kontribusi

- Tambahkan pemeriksaan keamanan lebih banyak (misalnya, keamanan DNS, keamanan email)
- Tingkatkan algoritma penilaian risiko
- Tambahkan dukungan untuk pemindaian domain batch
- Implementasi audit terjadwal
- Tambahkan format ekspor lebih banyak (PDF, JSON)
- Tingkatkan error handling dan logging
- Tambahkan dukungan internasionalisasi (i18n)

---

## 🐛 Laporan Bug & Permintaan Fitur

Silakan gunakan tab GitHub Issues untuk melaporkan bug atau meminta fitur. Saat melaporkan bug, sertakan:
- Sistem operasi dan versi Python
- Pesan error lengkap
- Langkah-langkah untuk mereproduksi masalah
- Perilaku yang diharapkan vs aktual

---

## 📄 Lisensi

Proyek ini adalah open source dan tersedia di bawah **Lisensi MIT**.

```
MIT License

Copyright (c) 2025 Desa-Secure 2025 Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👨‍💻 Penulis & Pengakuan

**Proyek**: Desa-Secure 2025  
**Tujuan**: Proyek Akademik - Audit Teknologi & Sistem Informasi  
**Semester**: 5 - 2025  
**Fokus**: Keamanan Ekosistem Digital Desa Indonesia

### Terima Kasih Khusus

- Administrator desa Indonesia yang bekerja untuk mendigitalisasi layanan mereka
- Komunitas open-source untuk tool dan library yang luar biasa
- Penasihat akademik untuk panduan tentang audit sistem informasi
- Semua kontributor dan pengguna proyek ini

---

## 📞 Kontak & Dukungan

Untuk pertanyaan, dukungan, atau peluang kolaborasi:

- **GitHub**: Buat repository dan update URL di sini
- **Proyek**: Fokus pada Ekosistem Digital Desa Indonesia
- **Semester**: 5 - Audit Teknologi & Sistem Informasi

---

## 🗺️ Roadmap

### Versi 1.0 (Saat Ini)
- ✅ Audit domain dasar
- ✅ Pemeriksaan SSL/TLS
- ✅ Pemindaian port
- ✅ Analisis header keamanan
- ✅ Sistem penilaian risiko
- ✅ Dashboard interaktif
- ✅ Fungsionalitas ekspor

### Versi 2.0 (Direncanakan)
- 🔄 Pemindaian domain batch
- 🔄 Audit terjadwal
- 🔄 Pelacakan data historis
- 🔄 Notifikasi email
- 🔄 API endpoints
- 🔄 Peningkatan desain responsif mobile

### Versi 3.0 (Masa Depan)
- 🔮 Prediksi risiko berbasis machine learning
- 🔮 Integrasi dengan threat intelligence feeds
- 🔮 Pemindaian kerentanan lanjutan
- 🔮 Pelaporan kepatuhan (ISO 27001, dll.)
- 🔮 Dukungan multi-bahasa

---

## 📖 Referensi & Sumber Daya

### Ekosistem Digital Desa Indonesia
- [Sistem Informasi Desa Official](https://sid.kemendesa.go.id/)
- [Kementerian Desa PDTT](https://kemendesa.go.id/)

### Standar Keamanan
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls](https://www.cisecurity.org/controls)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Dokumentasi Teknis
- [Dokumentasi Streamlit](https://docs.streamlit.io/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

---

## 💡 FAQ

**T: Bisakah saya menggunakan tool ini untuk tujuan komersial?**  
J: Ya, ini adalah software open-source di bawah Lisensi MIT. Namun, selalu pastikan otorisasi yang tepat sebelum audit.

**T: Apakah tool ini membuat perubahan pada domain target?**  
J: Tidak, ini adalah tool reconnaissance pasif yang hanya membaca informasi yang tersedia secara publik.

**T: Apakah data audit saya disimpan di mana pun?**  
J: Tidak, semua audit dilakukan secara real-time dan tidak ada data yang disimpan di server mana pun.

**T: Bisakah saya menambahkan lebih banyak port untuk dipindai?**  
J: Ya! Anda dapat memodifikasi dictionary `ports_to_check` di fungsi `scan_common_ports()`.

**T: Mengapa hanya mendukung domain .desa.id?**  
J: Ini by design untuk fokus khusus pada Sistem Informasi Desa Indonesia. Anda dapat memodifikasi fungsi validasi untuk mendukung domain lain.

---

## 🎓 Penggunaan Pendidikan

Tool ini sempurna untuk:
- Mata kuliah audit sistem informasi
- Pelatihan keamanan siber
- Praktik penetration testing (pada target yang diotorisasi)
- Memahami teknik OSINT
- Belajar pemrograman keamanan Python
- Pengembangan dashboard Streamlit

---

<div align="center">

### 🔒 Dibuat dengan ❤️ untuk Keamanan Digital Desa Indonesia

**Desa-Secure 2025** | Membuat Ekosistem Digital Desa Lebih Aman

⭐ Beri bintang repo ini jika Anda merasa berguna!

</div>
#   d e s a - s e c u r e - 2 0 2 5  
 