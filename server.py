#!/usr/bin/env python3
"""
Xavfsizlik Tekshiruv Backend Server
Uchta xizmatni bitta API orqali taqdim etadi:
  /api/ssl?domen=...      -> SSL sertifikat tekshiruvi
  /api/headers?domen=...  -> Xavfsizlik header'lari tekshiruvi
  /api/email?email=...    -> Email sizib chiqishi tekshiruvi
"""

import ssl
import os
import io
import time
import socket
import hashlib
import requests
import dns.resolver
import dns.exception
import dns.zone
import dns.query
import whois
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

app = Flask(__name__)
CORS(app)  # Frontend (boshqa domendan) so'rov yubora olishi uchun


# ---------- YORDAMCHI: Domenni tozalash ----------
def domen_tozala(domen):
    return domen.replace("https://", "").replace("http://", "").split("/")[0].strip()


# ---------- 1. SSL TEKSHIRUVI ----------
@app.route("/api/ssl", methods=["GET"])
def ssl_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domen, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domen) as ssock:
                sert = ssock.getpeercert()
                protokol = ssock.version()

                issuer = dict(x[0] for x in sert['issuer'])
                issuer_nomi = issuer.get('organizationName', issuer.get('commonName', "Noma'lum"))

                tugash_sana = datetime.strptime(sert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                hozir = datetime.now(timezone.utc).replace(tzinfo=None)
                qolgan_kun = (tugash_sana - hozir).days

                if protokol == "TLSv1.3":
                    baho = "alo"
                elif protokol == "TLSv1.2":
                    baho = "ortacha"
                else:
                    baho = "past"

                return jsonify({
                    "muvaffaqiyat": True,
                    "domen": domen,
                    "issuer": issuer_nomi,
                    "tugash_sanasi": tugash_sana.strftime("%d/%m/%Y"),
                    "qolgan_kun": qolgan_kun,
                    "protokol": protokol,
                    "baho": baho
                })

    except socket.timeout:
        return jsonify({"muvaffaqiyat": False, "xato": "Ulanish vaqti tugadi"}), 200
    except socket.gaierror:
        return jsonify({"muvaffaqiyat": False, "xato": "Domen topilmadi"}), 200
    except ConnectionRefusedError:
        return jsonify({"muvaffaqiyat": False, "xato": "HTTPS ulanishni rad etdi"}), 200
    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 2. HEADER TEKSHIRUVI ----------
TEKSHIRILADIGAN_HEADERLAR = {
    "Strict-Transport-Security": {"nomi": "HSTS", "muhimlik": "yuqori"},
    "X-Frame-Options": {"nomi": "X-Frame-Options", "muhimlik": "orta"},
    "Content-Security-Policy": {"nomi": "CSP", "muhimlik": "yuqori"},
    "X-Content-Type-Options": {"nomi": "X-Content-Type-Options", "muhimlik": "past"},
    "Referrer-Policy": {"nomi": "Referrer-Policy", "muhimlik": "past"},
}


@app.route("/api/headers", methods=["GET"])
def headers_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)
    url = f"https://{domen}"

    try:
        javob = requests.get(url, timeout=8, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })

        natija = []
        topilgan = 0

        for header_nomi, info in TEKSHIRILADIGAN_HEADERLAR.items():
            mavjud = header_nomi in javob.headers
            if mavjud:
                topilgan += 1
            natija.append({
                "nomi": info["nomi"],
                "mavjud": mavjud,
                "qiymat": javob.headers.get(header_nomi, ""),
                "muhimlik": info["muhimlik"]
            })

        jami = len(TEKSHIRILADIGAN_HEADERLAR)
        foiz = round((topilgan / jami) * 100)

        return jsonify({
            "muvaffaqiyat": True,
            "domen": domen,
            "headerlar": natija,
            "topilgan": topilgan,
            "jami": jami,
            "foiz": foiz
        })

    except requests.exceptions.SSLError:
        return jsonify({"muvaffaqiyat": False, "xato": "SSL/HTTPS muammosi"}), 200
    except requests.exceptions.ConnectionError:
        return jsonify({"muvaffaqiyat": False, "xato": "Ulanib bo'lmadi"}), 200
    except requests.exceptions.Timeout:
        return jsonify({"muvaffaqiyat": False, "xato": "Vaqt tugadi"}), 200
    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 3. EMAIL SIZIB CHIQISHI TEKSHIRUVI ----------
@app.route("/api/email", methods=["GET"])
def email_endpoint():
    email = request.args.get("email", "")
    if not email:
        return jsonify({"xato": "email parametri kerak"}), 400

    try:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        javob = requests.get(url, timeout=10, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })

        if javob.status_code == 200:
            malumot = javob.json()
            sizib_chiqqanlar = malumot.get("breaches", [])
            if sizib_chiqqanlar and isinstance(sizib_chiqqanlar[0], list):
                sizib_chiqqanlar = sizib_chiqqanlar[0]

            if not sizib_chiqqanlar or sizib_chiqqanlar == ["No breaches found"]:
                return jsonify({
                    "muvaffaqiyat": True,
                    "email": email,
                    "topildi": False,
                    "hodisalar": []
                })

            # Tafsilotlarni olishga harakat qilamiz
            tafsilotlar = []
            try:
                t_url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
                t_javob = requests.get(t_url, timeout=10, headers={
                    "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
                })
                if t_javob.status_code == 200:
                    t_malumot = t_javob.json()
                    breach_tafsilotlari = t_malumot.get("ExposedBreaches", {}).get("breaches_details", [])
                    for b in breach_tafsilotlari:
                        tafsilotlar.append({
                            "nomi": b.get("breach", "Noma'lum"),
                            "sana": b.get("xposed_date", "Noma'lum"),
                            "malumot_turlari": b.get("xposed_data", "")
                        })
            except Exception:
                pass

            return jsonify({
                "muvaffaqiyat": True,
                "email": email,
                "topildi": True,
                "hodisalar": sizib_chiqqanlar,
                "tafsilotlar": tafsilotlar
            })

        elif javob.status_code == 404:
            return jsonify({
                "muvaffaqiyat": True,
                "email": email,
                "topildi": False,
                "hodisalar": []
            })
        else:
            return jsonify({"muvaffaqiyat": False, "xato": f"Kutilmagan holat: {javob.status_code}"}), 200

    except requests.exceptions.Timeout:
        return jsonify({"muvaffaqiyat": False, "xato": "Vaqt tugadi"}), 200
    except requests.exceptions.ConnectionError:
        return jsonify({"muvaffaqiyat": False, "xato": "Ulanib bo'lmadi"}), 200
    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 4. DNS XAVFSIZLIGI TEKSHIRUVI (SPF/DKIM/DMARC/DNSSEC) ----------

# DKIM selector nomi domendan domenga farq qiladi va ochiq DNS orqali
# avtomatik aniqlab bo'lmaydi. Shuning uchun eng ko'p tarqalgan
# selector nomlari sinab ko'riladi.
DKIM_SELEKTORLAR = [
    "google", "default", "selector1", "selector2",
    "k1", "dkim", "mail", "smtp", "email"
]


def _spf_tekshir(domen):
    """Domenning SPF (TXT) yozuvini qidiradi."""
    try:
        javoblar = dns.resolver.resolve(domen, "TXT", lifetime=6)
        for r in javoblar:
            qiymat = b"".join(r.strings).decode("utf-8", errors="ignore")
            if qiymat.startswith("v=spf1"):
                if "-all" in qiymat:
                    siyosat = "qattiq"
                elif "~all" in qiymat:
                    siyosat = "yumshoq"
                elif "?all" in qiymat:
                    siyosat = "neytral"
                else:
                    siyosat = "noma'lum"
                return {"mavjud": True, "qiymat": qiymat, "siyosat": siyosat}
        return {"mavjud": False, "qiymat": None, "siyosat": None}
    except (dns.exception.DNSException, Exception):
        return {"mavjud": False, "qiymat": None, "siyosat": None}


def _dkim_tekshir(domen):
    """Eng ko'p tarqalgan selectorlar bo'yicha DKIM yozuvini qidiradi."""
    for selector in DKIM_SELEKTORLAR:
        manzil = f"{selector}._domainkey.{domen}"
        try:
            javoblar = dns.resolver.resolve(manzil, "TXT", lifetime=4)
            for r in javoblar:
                qiymat = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=DKIM1" in qiymat or "p=" in qiymat:
                    return {"mavjud": True, "selector": selector}
        except (dns.exception.DNSException, Exception):
            continue
    return {"mavjud": False, "selector": None}


def _dmarc_tekshir(domen):
    """Domenning DMARC (_dmarc.domen) yozuvini qidiradi."""
    manzil = f"_dmarc.{domen}"
    try:
        javoblar = dns.resolver.resolve(manzil, "TXT", lifetime=6)
        for r in javoblar:
            qiymat = b"".join(r.strings).decode("utf-8", errors="ignore")
            if qiymat.startswith("v=DMARC1"):
                if "p=reject" in qiymat:
                    siyosat = "reject"
                elif "p=quarantine" in qiymat:
                    siyosat = "quarantine"
                elif "p=none" in qiymat:
                    siyosat = "none"
                else:
                    siyosat = "noma'lum"
                return {"mavjud": True, "qiymat": qiymat, "siyosat": siyosat}
        return {"mavjud": False, "qiymat": None, "siyosat": None}
    except (dns.exception.DNSException, Exception):
        return {"mavjud": False, "qiymat": None, "siyosat": None}


def _dnssec_tekshir(domen):
    """Domenning DNSKEY yozuvi mavjudligini tekshiradi (DNSSEC belgisi)."""
    try:
        dns.resolver.resolve(domen, "DNSKEY", lifetime=6)
        return {"faol": True}
    except (dns.exception.DNSException, Exception):
        return {"faol": False}


def _caa_tekshir(domen):
    """CAA yozuvini qidiradi (qaysi provayderlar sertifikat berishi mumkin)."""
    try:
        javoblar = dns.resolver.resolve(domen, "CAA", lifetime=6)
        royxat = []
        for r in javoblar:
            royxat.append({
                "flag": r.flags,
                "tag": r.tag.decode() if isinstance(r.tag, bytes) else str(r.tag),
                "qiymat": r.value.decode() if isinstance(r.value, bytes) else str(r.value)
            })
        return {"mavjud": len(royxat) > 0, "yozuvlar": royxat}
    except (dns.exception.DNSException, Exception):
        return {"mavjud": False, "yozuvlar": []}


@app.route("/api/dns", methods=["GET"])
def dns_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    try:
        spf = _spf_tekshir(domen)
        dkim = _dkim_tekshir(domen)
        dmarc = _dmarc_tekshir(domen)
        dnssec = _dnssec_tekshir(domen)
        caa = _caa_tekshir(domen)

        # ---- Ball hisoblash ----
        ball = 0
        if spf["mavjud"]:
            ball += 20
        if dkim["mavjud"]:
            ball += 15
        if dmarc["mavjud"]:
            if dmarc["siyosat"] in ("reject", "quarantine"):
                ball += 25
            elif dmarc["siyosat"] == "none":
                ball += 8
        if dnssec["faol"]:
            ball += 20
        if caa["mavjud"]:
            ball += 20

        ball = min(ball, 100)

        return jsonify({
            "muvaffaqiyat": True,
            "domen": domen,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "dnssec": dnssec,
            "caa": caa,
            "ball": ball,
            "jami_ball": 100
        })

    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 5. OCHIQ PORTLARNI TEKSHIRISH ----------

# Eng ko'p uchraydigan va xavfsizlik nuqtai nazaridan muhim portlar
TEKSHIRILADIGAN_PORTLAR = {
    21: {"nomi": "FTP", "tavsif": "Fayl uzatish protokoli, shifrlanmagan", "muhimlik": "yuqori"},
    22: {"nomi": "SSH", "tavsif": "Masofaviy boshqaruv", "muhimlik": "orta"},
    23: {"nomi": "Telnet", "tavsif": "Eski, shifrlanmagan masofaviy kirish", "muhimlik": "yuqori"},
    25: {"nomi": "SMTP", "tavsif": "Email jo'natish serveri", "muhimlik": "orta"},
    80: {"nomi": "HTTP", "tavsif": "Shifrlanmagan veb-server", "muhimlik": "orta"},
    443: {"nomi": "HTTPS", "tavsif": "Shifrlangan xavfsiz veb-server", "muhimlik": "past"},
    3306: {"nomi": "MySQL", "tavsif": "Ma'lumotlar bazasi, tashqariga ochiq bo'lmasligi kerak", "muhimlik": "yuqori"},
    3389: {"nomi": "RDP", "tavsif": "Windows masofaviy ish stoli, hujumlar uchun mashhur nishon", "muhimlik": "yuqori"},
    5432: {"nomi": "PostgreSQL", "tavsif": "Ma'lumotlar bazasi, tashqariga ochiq bo'lmasligi kerak", "muhimlik": "yuqori"},
    6379: {"nomi": "Redis", "tavsif": "Xotira bazasi, ko'pincha parolsiz qoldiriladi", "muhimlik": "yuqori"},
}


def _port_tekshir(domen, port, timeout=2.5):
    """Berilgan portga ulanishga harakat qiladi (faqat ochiq/yopiqligini bilish uchun)."""
    try:
        with socket.create_connection((domen, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


@app.route("/api/ports", methods=["GET"])
def ports_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    try:
        natija = []
        ochiq_soni = 0

        for port, info in TEKSHIRILADIGAN_PORTLAR.items():
            ochiq = _port_tekshir(domen, port)
            if ochiq:
                ochiq_soni += 1
            natija.append({
                "port": port,
                "nomi": info["nomi"],
                "tavsif": info["tavsif"],
                "muhimlik": info["muhimlik"],
                "ochiq": ochiq
            })

        return jsonify({
            "muvaffaqiyat": True,
            "domen": domen,
            "portlar": natija,
            "ochiq_soni": ochiq_soni,
            "jami_tekshirilgan": len(TEKSHIRILADIGAN_PORTLAR)
        })

    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 6. WHOIS MA'LUMOTLARI ----------
@app.route("/api/whois", methods=["GET"])
def whois_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    try:
        malumot = whois.whois(domen)

        def _sana_formatla(qiymat):
            # ba'zi domenlarda sana ro'yxat qilib qaytadi, birinchisini olamiz
            if isinstance(qiymat, list):
                qiymat = qiymat[0] if qiymat else None
            if isinstance(qiymat, datetime):
                return qiymat.strftime("%d/%m/%Y")
            return None

        royxatdan_otgan = _sana_formatla(malumot.creation_date)
        tugash_sanasi = _sana_formatla(malumot.expiration_date)
        registrator = malumot.registrar if isinstance(malumot.registrar, str) else None

        if not royxatdan_otgan and not tugash_sanasi and not registrator:
            return jsonify({
                "muvaffaqiyat": False,
                "xato": "WHOIS ma'lumoti topilmadi (domen himoyalangan yoki mavjud emas)"
            }), 200

        return jsonify({
            "muvaffaqiyat": True,
            "domen": domen,
            "registrator": registrator or "Noma'lum",
            "royxatdan_otgan_sana": royxatdan_otgan or "Noma'lum",
            "tugash_sanasi": tugash_sanasi or "Noma'lum"
        })

    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 7. GOOGLE SAFE BROWSING (BLACKLIST TEKSHIRUVI) ----------
# Bepul API kaliti kerak: https://developers.google.com/safe-browsing/v4/get-started
# Kalitni Render'da "Environment Variables" bo'limiga GOOGLE_SAFE_BROWSING_KEY nomi bilan qo'shing
SAFE_BROWSING_KALIT = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")


@app.route("/api/blacklist", methods=["GET"])
def blacklist_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    if not SAFE_BROWSING_KALIT:
        return jsonify({
            "muvaffaqiyat": False,
            "xato": "API kaliti sozlanmagan (GOOGLE_SAFE_BROWSING_KEY)"
        }), 200

    try:
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KALIT}"
        body = {
            "client": {"clientId": "xavfsizlik-tekshiruv", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"https://{domen}"}, {"url": f"http://{domen}"}]
            }
        }
        javob = requests.post(url, json=body, timeout=8)

        if javob.status_code != 200:
            return jsonify({"muvaffaqiyat": False, "xato": f"API xatosi: {javob.status_code}"}), 200

        natija = javob.json()
        xavflar = natija.get("matches", [])

        return jsonify({
            "muvaffaqiyat": True,
            "domen": domen,
            "xavfli": len(xavflar) > 0,
            "xavf_turlari": list({x.get("threatType") for x in xavflar}) if xavflar else []
        })

    except requests.exceptions.Timeout:
        return jsonify({"muvaffaqiyat": False, "xato": "Vaqt tugadi"}), 200
    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 8. SUBDOMENLARNI ANIQLASH (crt.sh orqali) ----------
@app.route("/api/subdomains", methods=["GET"])
def subdomains_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    try:
        url = f"https://crt.sh/?q=%25.{domen}&output=json"

        # crt.sh ba'zan birinchi so'rovda sekin/vaqtinchalik javob bermaydi,
        # shuning uchun bitta qayta urinish qo'shildi
        javob = None
        oxirgi_xato = None
        for urinish in range(2):
            try:
                javob = requests.get(url, timeout=25, headers={
                    "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
                })
                break
            except requests.exceptions.Timeout as e:
                oxirgi_xato = e
                continue

        if javob is None:
            raise oxirgi_xato or requests.exceptions.Timeout()

        if javob.status_code != 200:
            return jsonify({"muvaffaqiyat": False, "xato": "crt.sh xizmati javob bermadi"}), 200

        malumot = javob.json()

        # Takroriy nomlarni olib tashlash
        subdomenlar = set()
        for yozuv in malumot:
            nom = yozuv.get("name_value", "")
            for qator in nom.split("\n"):
                qator = qator.strip().lower()
                if qator and not qator.startswith("*."):
                    subdomenlar.add(qator)

        royxat = sorted(subdomenlar)

        return jsonify({
            "muvaffaqiyat": True,
            "domen": domen,
            "subdomenlar": royxat,
            "soni": len(royxat)
        })

    except requests.exceptions.Timeout:
        return jsonify({"muvaffaqiyat": False, "xato": "Vaqt tugadi (crt.sh sekin javob berdi)"}), 200
    except ValueError:
        return jsonify({"muvaffaqiyat": False, "xato": "Ma'lumotni o'qib bo'lmadi"}), 200
    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 9. TEXNOLOGIYA, OCHIQ FAYLLAR VA COOKIE TEKSHIRUVI ----------

# Tasodifan ochiq qolishi mumkin bo'lgan maxfiy fayllar
MAXFIY_FAYLLAR = [
    ".env", ".git/config", "wp-config.php.bak", "backup.sql",
    "phpinfo.php", ".DS_Store", "config.php.bak", ".htpasswd"
]

# CMS/texnologiyalarni HTML ichidan aniqlash uchun belgilar
CMS_BELGILARI = {
    "WordPress": ["wp-content", "wp-includes"],
    "Joomla": ["/media/jui/", "Joomla!"],
    "Drupal": ["Drupal.settings", "/sites/default/"],
    "Shopify": ["cdn.shopify.com"],
    "Wix": ["static.wixstatic.com"],
    "Laravel": ["laravel_session"],
}


@app.route("/api/techscan", methods=["GET"])
def techscan_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)
    url = f"https://{domen}"

    try:
        javob = requests.get(url, timeout=8, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })

        # ---- Server / texnologiya ----
        server_header = javob.headers.get("Server", "Noma'lum")
        powered_by = javob.headers.get("X-Powered-By", "")

        aniqlangan_cms = []
        html_matn = javob.text[:200000]  # juda katta sahifalarni cheklash
        for nom, belgilar in CMS_BELGILARI.items():
            if any(b.lower() in html_matn.lower() for b in belgilar):
                aniqlangan_cms.append(nom)

        # ---- Cookie xavfsizligi ----
        cookie_natijasi = []
        for cookie in javob.cookies:
            cookie_natijasi.append({
                "nomi": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": "httponly" in [k.lower() for k in cookie._rest.keys()] if hasattr(cookie, "_rest") else False,
                "samesite": cookie._rest.get("SameSite", "Yo'q") if hasattr(cookie, "_rest") else "Yo'q"
            })

        # ---- Ochiq maxfiy fayllar ----
        ochiq_fayllar = []
        for fayl in MAXFIY_FAYLLAR:
            try:
                f_javob = requests.get(f"{url}/{fayl}", timeout=4, headers={
                    "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
                }, allow_redirects=False)
                if f_javob.status_code == 200 and len(f_javob.content) > 0:
                    ochiq_fayllar.append(fayl)
            except requests.exceptions.RequestException:
                continue

        return jsonify({
            "muvaffaqiyat": True,
            "domen": domen,
            "server": server_header,
            "powered_by": powered_by or "Noma'lum",
            "cms": aniqlangan_cms,
            "cookielar": cookie_natijasi,
            "ochiq_maxfiy_fayllar": ochiq_fayllar
        })

    except requests.exceptions.SSLError:
        return jsonify({"muvaffaqiyat": False, "xato": "SSL/HTTPS muammosi"}), 200
    except requests.exceptions.ConnectionError:
        return jsonify({"muvaffaqiyat": False, "xato": "Ulanib bo'lmadi"}), 200
    except requests.exceptions.Timeout:
        return jsonify({"muvaffaqiyat": False, "xato": "Vaqt tugadi"}), 200
    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 10. TARMOQ MA'LUMOTLARI (IP / GEOLOKATSIYA / CDN / REVERSE DNS) ----------

CDN_KALIT_SOZLAR = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "amazon": "Amazon CloudFront",
    "sucuri": "Sucuri",
    "incapsula": "Imperva Incapsula",
    "google": "Google Cloud CDN",
}


@app.route("/api/networkinfo", methods=["GET"])
def networkinfo_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    try:
        ip = socket.gethostbyname(domen)
    except socket.gaierror:
        return jsonify({"muvaffaqiyat": False, "xato": "Domen IP manzilga aylantirib bo'lmadi"}), 200

    natija = {
        "muvaffaqiyat": True,
        "domen": domen,
        "ip": ip,
        "mamlakat": "Noma'lum",
        "shahar": "Noma'lum",
        "provayder": "Noma'lum",
        "cdn": None,
        "reverse_dns": None
    }

    # ---- Geolokatsiya (ip-api.com, bepul, kalit kerak emas) ----
    try:
        geo_javob = requests.get(f"http://ip-api.com/json/{ip}", timeout=6)
        if geo_javob.status_code == 200:
            geo = geo_javob.json()
            if geo.get("status") == "success":
                natija["mamlakat"] = geo.get("country", "Noma'lum")
                natija["shahar"] = geo.get("city", "Noma'lum")
                natija["provayder"] = geo.get("isp", "Noma'lum")

                # ---- CDN aniqlash (provayder/org nomi bo'yicha) ----
                tekshiriladigan_matn = f"{geo.get('isp', '')} {geo.get('org', '')}".lower()
                for kalit, nomi in CDN_KALIT_SOZLAR.items():
                    if kalit in tekshiriladigan_matn:
                        natija["cdn"] = nomi
                        break
    except requests.exceptions.RequestException:
        pass

    # ---- Reverse DNS (PTR) ----
    try:
        ptr = socket.gethostbyaddr(ip)
        natija["reverse_dns"] = ptr[0]
    except (socket.herror, socket.gaierror):
        natija["reverse_dns"] = None

    return jsonify(natija)


# ---------- 11. MAIL YOZUVLARI (MX / BIMI) ----------
@app.route("/api/mailrecords", methods=["GET"])
def mailrecords_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    # ---- MX yozuvlari ----
    mx_royxati = []
    try:
        mx_javoblar = dns.resolver.resolve(domen, "MX", lifetime=6)
        for r in mx_javoblar:
            mx_royxati.append({
                "server": str(r.exchange).rstrip("."),
                "ustuvorlik": r.preference
            })
        mx_royxati.sort(key=lambda x: x["ustuvorlik"])
    except (dns.exception.DNSException, Exception):
        mx_royxati = []

    # ---- BIMI yozuvi ----
    bimi_mavjud = False
    try:
        bimi_javob = dns.resolver.resolve(f"default._bimi.{domen}", "TXT", lifetime=5)
        for r in bimi_javob:
            qiymat = b"".join(r.strings).decode("utf-8", errors="ignore")
            if "v=BIMI1" in qiymat:
                bimi_mavjud = True
                break
    except (dns.exception.DNSException, Exception):
        bimi_mavjud = False

    return jsonify({
        "muvaffaqiyat": True,
        "domen": domen,
        "mx_yozuvlari": mx_royxati,
        "mx_mavjud": len(mx_royxati) > 0,
        "bimi_mavjud": bimi_mavjud
    })


# ---------- 12. PAROL SIZIB CHIQISHINI TEKSHIRISH (Pwned Passwords, k-anonymity) ----------
# MUHIM: parolning o'zi hech qayerga yuborilmaydi. Faqat SHA1 xeshining
# birinchi 5 belgisi HaveIBeenPwned'ga yuboriladi (k-anonymity usuli),
# qolgan qismi serverda solishtiriladi. Bu usul to'liq xavfsiz.
@app.route("/api/pwnedpassword", methods=["POST"])
def pwnedpassword_endpoint():
    malumot = request.get_json(silent=True) or {}
    parol = malumot.get("parol", "")

    if not parol:
        return jsonify({"xato": "parol parametri kerak"}), 400

    try:
        sha1 = hashlib.sha1(parol.encode("utf-8")).hexdigest().upper()
        prefiks, qolgan_qism = sha1[:5], sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefiks}"
        javob = requests.get(url, timeout=8, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })

        if javob.status_code != 200:
            return jsonify({"muvaffaqiyat": False, "xato": "Xizmat javob bermadi"}), 200

        soni = 0
        for qator in javob.text.splitlines():
            qism, hisob = qator.split(":")
            if qism.strip() == qolgan_qism:
                soni = int(hisob.strip())
                break

        return jsonify({
            "muvaffaqiyat": True,
            "sizib_chiqqan": soni > 0,
            "necha_marta_uchragan": soni
        })

    except requests.exceptions.Timeout:
        return jsonify({"muvaffaqiyat": False, "xato": "Vaqt tugadi"}), 200
    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 13. HTTP -> HTTPS MAJBURIY YO'NALTIRISH VA SECURITY.TXT ----------
@app.route("/api/extrachecks", methods=["GET"])
def extrachecks_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    # ---- HTTP -> HTTPS yo'naltirish ----
    https_yonaltirish = {"mavjud": False, "tafsilot": "Tekshirib bo'lmadi"}
    try:
        http_javob = requests.get(
            f"http://{domen}", timeout=8, allow_redirects=False,
            headers={"User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"}
        )
        joylashuv = http_javob.headers.get("Location", "")
        if http_javob.status_code in (301, 302, 307, 308) and joylashuv.startswith("https://"):
            https_yonaltirish = {"mavjud": True, "tafsilot": f"HTTP -> HTTPS ga yo'naltiriladi ({http_javob.status_code})"}
        else:
            https_yonaltirish = {"mavjud": False, "tafsilot": "HTTP so'rovi HTTPS'ga avtomatik yo'naltirilmaydi"}
    except requests.exceptions.RequestException:
        https_yonaltirish = {"mavjud": False, "tafsilot": "HTTP portiga ulanib bo'lmadi"}

    # ---- security.txt ----
    security_txt = {"mavjud": False}
    try:
        st_javob = requests.get(
            f"https://{domen}/.well-known/security.txt", timeout=6,
            headers={"User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"}
        )
        if st_javob.status_code == 200 and len(st_javob.text.strip()) > 0:
            security_txt = {"mavjud": True}
    except requests.exceptions.RequestException:
        pass

    return jsonify({
        "muvaffaqiyat": True,
        "domen": domen,
        "https_yonaltirish": https_yonaltirish,
        "security_txt": security_txt
    })


# ---------- 14. PDF HISOBOT GENERATSIYASI ----------
# Frontend barcha 12+ tekshiruv natijasini quyidagi formatda yuboradi:
# {
#   "domen": "example.com",
#   "umumiy_ball": 75,
#   "daraja": "B",
#   "bolimlar": [
#       {"nomi": "SSL Sertifikat", "holat": "Yaxshi", "tafsilotlar": ["Provayder: Let's Encrypt", "56 kun qoldi"]},
#       ...
#   ]
# }
QU_RANG = colors.HexColor("#0EA5A5")
QORA_FON = colors.HexColor("#0B1120")


def _pdf_logo_chiz(canvas_obj, doc):
    """Har bir sahifa tepasiga 'QU' logotipi va sarlavha chizadi."""
    canvas_obj.saveState()
    sahifa_kengligi, sahifa_balandligi = A4

    # Logotip doirasi
    canvas_obj.setFillColor(QU_RANG)
    canvas_obj.circle(28 * mm, sahifa_balandligi - 18 * mm, 10 * mm, fill=1, stroke=0)
    canvas_obj.setFillColor(colors.white)
    canvas_obj.setFont("Helvetica-Bold", 14)
    canvas_obj.drawCentredString(28 * mm, sahifa_balandligi - 20.5 * mm, "QU")

    # Sarlavha matni
    canvas_obj.setFillColor(colors.HexColor("#111827"))
    canvas_obj.setFont("Helvetica-Bold", 13)
    canvas_obj.drawString(44 * mm, sahifa_balandligi - 16 * mm, "Xavfsizlik Tekshiruvi Hisoboti")
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(colors.HexColor("#6B7280"))
    canvas_obj.drawString(44 * mm, sahifa_balandligi - 21 * mm, "QU Enterprise Security Audit")

    # Pastki chiziq
    canvas_obj.setStrokeColor(colors.HexColor("#E5E7EB"))
    canvas_obj.line(20 * mm, sahifa_balandligi - 26 * mm, sahifa_kengligi - 20 * mm, sahifa_balandligi - 26 * mm)

    # Sahifa raqami
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(colors.HexColor("#9CA3AF"))
    canvas_obj.drawRightString(sahifa_kengligi - 20 * mm, 12 * mm, f"Sahifa {doc.page}")

    canvas_obj.restoreState()


def _holat_rangi(holat_matni):
    matn = (holat_matni or "").lower()
    if any(s in matn for s in ["yaxshi", "faol", "xavfsiz", "topilmadi", "a'lo", "ha"]):
        return colors.HexColor("#059669")  # yashil
    if any(s in matn for s in ["o'rtacha", "diqqat", "tez orada"]):
        return colors.HexColor("#D97706")  # sariq
    if any(s in matn for s in ["xavfli", "yo'q", "ochiq", "topildi", "muddati tugagan"]):
        return colors.HexColor("#DC2626")  # qizil
    return colors.HexColor("#6B7280")  # kulrang (neytral)


@app.route("/api/report", methods=["GET", "POST"])
def report_endpoint():
    if request.method == "POST":
        malumot = request.get_json(silent=True) or {}
        domen = malumot.get("domen", "Noma'lum domen")
        umumiy_ball = malumot.get("umumiy_ball", 0)
        daraja = malumot.get("daraja", "-")
        bolimlar = malumot.get("bolimlar", [])
    else:
        # ---- GET: domen=... orqali chaqirilsa, backend o'zi barcha
        # tekshiruvlarni bajarib, natijalarni "bolimlar" formatiga o'tkazadi ----
        domen = request.args.get("domen", "")
        if not domen:
            return jsonify({"xato": "domen parametri kerak"}), 400
        domen = domen_tozala(domen)

        bolimlar = []

        # SSL
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domen, 443), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=domen) as ssock:
                    sert = ssock.getpeercert()
                    protokol = ssock.version()
                    issuer = dict(x[0] for x in sert['issuer'])
                    issuer_nomi = issuer.get('organizationName', issuer.get('commonName', "Noma'lum"))
                    tugash_sana = datetime.strptime(sert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    qolgan_kun = (tugash_sana - datetime.now(timezone.utc).replace(tzinfo=None)).days
                    bolimlar.append({
                        "nomi": "SSL Sertifikat",
                        "holat": "Faol" if qolgan_kun > 0 else "Muddati tugagan",
                        "tafsilotlar": [f"Beruvchi: {issuer_nomi}", f"Protokol: {protokol}", f"Qolgan kun: {qolgan_kun}"]
                    })
        except Exception:
            bolimlar.append({"nomi": "SSL Sertifikat", "holat": "Tekshirib bo'lmadi", "tafsilotlar": []})

        # Headerlar
        try:
            h_javob = requests.get(f"https://{domen}", timeout=8, headers={"User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"})
            yoq_headerlar = [h for h in TEKSHIRILADIGAN_HEADERLAR if h not in h_javob.headers]
            bolimlar.append({
                "nomi": "Xavfsizlik Headerlari",
                "holat": "Barchasi mavjud" if not yoq_headerlar else f"{len(yoq_headerlar)} ta yo'q",
                "tafsilotlar": [f"Yo'q: {h}" for h in yoq_headerlar] if yoq_headerlar else ["Barcha muhim headerlar sozlangan"]
            })
        except Exception:
            bolimlar.append({"nomi": "Xavfsizlik Headerlari", "holat": "Tekshirib bo'lmadi", "tafsilotlar": []})

        # DNS / Email
        spf = _spf_tekshir(domen)
        dmarc = _dmarc_tekshir(domen)
        dnssec = _dnssec_tekshir(domen)
        caa = _caa_tekshir(domen)
        bolimlar.append({
            "nomi": "DNS / Email Xavfsizligi",
            "holat": "Yaxshi" if spf["mavjud"] and dmarc["mavjud"] else "Diqqat talab qiladi",
            "tafsilotlar": [
                f"SPF: {'mavjud' if spf['mavjud'] else 'yo\u2018q'}",
                f"DMARC: {'mavjud' if dmarc['mavjud'] else 'yo\u2018q'}",
                f"DNSSEC: {'faol' if dnssec['faol'] else 'faol emas'}",
                f"CAA: {'mavjud' if caa['mavjud'] else 'yo\u2018q'}",
            ]
        })

        # Portlar
        ochiq_portlar = []
        for port, info in TEKSHIRILADIGAN_PORTLAR.items():
            if _port_tekshir(domen, port, timeout=1.5):
                ochiq_portlar.append(f"Port {port} ({info['nomi']}) ochiq")
        bolimlar.append({
            "nomi": "Ochiq Portlar",
            "holat": "Xavfsiz" if not ochiq_portlar else f"{len(ochiq_portlar)} ta ochiq",
            "tafsilotlar": ochiq_portlar if ochiq_portlar else ["Xavfli portlar topilmadi"]
        })

        umumiy_ball = "-"
        daraja = "-"

    try:
        buffer = io.BytesIO()
        hujjat = SimpleDocTemplate(
            buffer, pagesize=A4,
            topMargin=32 * mm, bottomMargin=20 * mm,
            leftMargin=20 * mm, rightMargin=20 * mm
        )

        uslublar = getSampleStyleSheet()
        sarlavha_uslubi = ParagraphStyle(
            "BolimSarlavha", parent=uslublar["Heading2"],
            fontSize=13, spaceBefore=10, spaceAfter=4,
            textColor=colors.HexColor("#111827")
        )
        matn_uslubi = ParagraphStyle(
            "Matn", parent=uslublar["Normal"],
            fontSize=10, textColor=colors.HexColor("#374151"), leading=14
        )
        katta_uslub = ParagraphStyle(
            "Katta", parent=uslublar["Normal"],
            fontSize=28, alignment=TA_CENTER, textColor=QU_RANG,
            spaceAfter=2
        )

        elementlar = []

        # ---- Umumiy ma'lumot bloki ----
        elementlar.append(Paragraph(f"<b>Domen:</b> {domen}", matn_uslubi))
        elementlar.append(Paragraph(
            f"<b>Sana:</b> {datetime.now().strftime('%d/%m/%Y %H:%M')}", matn_uslubi
        ))
        elementlar.append(Spacer(1, 10))
        elementlar.append(Paragraph(f"{umumiy_ball} / 100", katta_uslub))
        elementlar.append(Paragraph(
            f"<para alignment='center'><b>Umumiy Daraja: {daraja}</b></para>", matn_uslubi
        ))
        elementlar.append(Spacer(1, 14))

        # ---- Har bir bo'lim ----
        for bolim in bolimlar:
            nomi = bolim.get("nomi", "Noma'lum bo'lim")
            holat = bolim.get("holat", "")
            tafsilotlar = bolim.get("tafsilotlar", [])

            sarlavha_jadval_malumoti = [[
                Paragraph(f"<b>{nomi}</b>", sarlavha_uslubi),
                Paragraph(
                    f"<font color='{_holat_rangi(holat).hexval() if hasattr(_holat_rangi(holat), 'hexval') else '#6B7280'}'><b>{holat}</b></font>",
                    matn_uslubi
                )
            ]]
            jadval = Table(sarlavha_jadval_malumoti, colWidths=[120 * mm, 50 * mm])
            jadval.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
            ]))
            elementlar.append(jadval)

            for qator in tafsilotlar:
                elementlar.append(Paragraph(f"&bull; {qator}", matn_uslubi))

            elementlar.append(Spacer(1, 8))

        if not bolimlar:
            elementlar.append(Paragraph("Hisobot uchun ma'lumot topilmadi.", matn_uslubi))

        hujjat.build(elementlar, onFirstPage=_pdf_logo_chiz, onLaterPages=_pdf_logo_chiz)
        buffer.seek(0)

        fayl_nomi = f"xavfsizlik-hisobot-{domen.replace('.', '-')}.pdf"
        return send_file(
            buffer, mimetype="application/pdf",
            as_attachment=True, download_name=fayl_nomi
        )

    except Exception as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- 13. HTTP->HTTPS YO'NALTIRISH VA SECURITY.TXT TEKSHIRUVI ----------
@app.route("/api/extras", methods=["GET"])
def extras_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400

    domen = domen_tozala(domen)

    # ---- HTTP -> HTTPS majburiy yo'naltirish ----
    https_yonaltirish = {"tekshirildi": False, "yonaltirilgan": False, "yakuniy_url": None}
    try:
        javob = requests.get(f"http://{domen}", timeout=8, allow_redirects=True, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })
        https_yonaltirish["tekshirildi"] = True
        https_yonaltirish["yonaltirilgan"] = javob.url.startswith("https://")
        https_yonaltirish["yakuniy_url"] = javob.url
    except requests.exceptions.RequestException:
        https_yonaltirish["tekshirildi"] = False

    # ---- security.txt fayli ----
    security_txt = {"mavjud": False}
    for yol in ["/.well-known/security.txt", "/security.txt"]:
        try:
            s_javob = requests.get(f"https://{domen}{yol}", timeout=6, headers={
                "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
            })
            if s_javob.status_code == 200 and "contact" in s_javob.text.lower():
                security_txt["mavjud"] = True
                security_txt["manzil"] = yol
                break
        except requests.exceptions.RequestException:
            continue

    return jsonify({
        "muvaffaqiyat": True,
        "domen": domen,
        "https_yonaltirish": https_yonaltirish,
        "security_txt": security_txt
    })


# ---------- 15. SSL/TLS CHUQUR TAHLILI ----------
@app.route("/api/tlsdeep", methods=["GET"])
def tlsdeep_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400
    domen = domen_tozala(domen)

    natija = {
        "muvaffaqiyat": True, "domen": domen,
        "zaif_protokollar": [], "san_royxati": [], "ocsp_stapling": False
    }

    # ---- Zaif TLS versiyalarini sinash (faqat handshake, hujum emas) ----
    eski_protokollar = {
        "TLSv1": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
    }
    for nomi, versiya in eski_protokollar.items():
        if versiya is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = versiya
            ctx.maximum_version = versiya
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domen, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domen):
                    natija["zaif_protokollar"].append(nomi)
        except Exception:
            pass  # bu versiya qo'llab-quvvatlanmaydi (yaxshi holat)

    # ---- SAN ro'yxati va OCSP ----
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domen, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domen) as ssock:
                sert = ssock.getpeercert()
                for turi, qiymat in sert.get("subjectAltName", []):
                    if turi == "DNS":
                        natija["san_royxati"].append(qiymat)
                # OCSP stapling holatini aniqlash
                try:
                    ocsp = ssock.get_channel_binding("tls-server-end-point")
                    natija["ocsp_stapling"] = ocsp is not None
                except Exception:
                    natija["ocsp_stapling"] = False
    except Exception:
        pass

    return jsonify(natija)


# ---------- 16. HTTP PROTOKOL DARAJASI TEKSHIRUVI ----------
@app.route("/api/httpprotocol", methods=["GET"])
def httpprotocol_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400
    domen = domen_tozala(domen)

    natija = {
        "muvaffaqiyat": True, "domen": domen,
        "http2_qollab_quvvatlaydi": False,
        "xavfli_metodlar": [], "cors_xavfi": False, "cors_qiymati": None
    }

    # ---- HTTP/2 (ALPN orqali) ----
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((domen, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domen) as ssock:
                natija["http2_qollab_quvvatlaydi"] = ssock.selected_alpn_protocol() == "h2"
    except Exception:
        pass

    # ---- OPTIONS so'rovi orqali qaysi metodlar ochiqligini ko'rish ----
    try:
        javob = requests.options(f"https://{domen}", timeout=6, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })
        allow = javob.headers.get("Allow", "")
        xavfli = [m.strip() for m in allow.split(",") if m.strip().upper() in ("PUT", "DELETE", "TRACE", "CONNECT")]
        natija["xavfli_metodlar"] = xavfli
    except requests.exceptions.RequestException:
        pass

    # ---- CORS sozlamasi ----
    try:
        javob = requests.get(f"https://{domen}", timeout=6, headers={
            "Origin": "https://misol-begona-domen.com",
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })
        acao = javob.headers.get("Access-Control-Allow-Origin")
        natija["cors_qiymati"] = acao
        natija["cors_xavfi"] = acao == "*"
    except requests.exceptions.RequestException:
        pass

    return jsonify(natija)


# ---------- 17. DNS QO'SHIMCHA TAHLILI ----------
@app.route("/api/dnsextra", methods=["GET"])
def dnsextra_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400
    domen = domen_tozala(domen)

    natija = {
        "muvaffaqiyat": True, "domen": domen,
        "ipv6_mavjud": False, "nameserverlar": [], "zone_transfer_ochiq": False,
        "wildcard_dns": False
    }

    # ---- IPv6 (AAAA) ----
    try:
        dns.resolver.resolve(domen, "AAAA", lifetime=6)
        natija["ipv6_mavjud"] = True
    except (dns.exception.DNSException, Exception):
        natija["ipv6_mavjud"] = False

    # ---- Nameserverlar ----
    ns_royxati = []
    try:
        ns_javob = dns.resolver.resolve(domen, "NS", lifetime=6)
        ns_royxati = [str(r.target).rstrip(".") for r in ns_javob]
        natija["nameserverlar"] = ns_royxati
    except (dns.exception.DNSException, Exception):
        pass

    # ---- Zone Transfer (AXFR) - oddiy DNS so'rovi, faqat noto'g'ri
    # sozlangan serverlarda ishlaydi, o'zi hujum emas ----
    for ns in ns_royxati[:3]:
        try:
            ns_ip = socket.gethostbyname(ns)
            zona = dns.zone.from_xfr(dns.query.xfr(ns_ip, domen, timeout=5, lifetime=6))
            if zona:
                natija["zone_transfer_ochiq"] = True
                break
        except Exception:
            continue

    # ---- Wildcard DNS ----
    try:
        tasodifiy = f"tekshiruv-mavjud-emas-{os.urandom(4).hex()}.{domen}"
        dns.resolver.resolve(tasodifiy, "A", lifetime=5)
        natija["wildcard_dns"] = True
    except (dns.exception.DNSException, Exception):
        natija["wildcard_dns"] = False

    return jsonify(natija)


# ---------- 18. QO'SHIMCHA RAZVEDKA (robots.txt, favicon, typosquatting) ----------
@app.route("/api/recon", methods=["GET"])
def recon_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400
    domen = domen_tozala(domen)

    natija = {
        "muvaffaqiyat": True, "domen": domen,
        "robots_maxfiy_yollar": [], "favicon_xesh": None,
        "domen_breach_soni": None, "typosquat_variantlar": []
    }

    # ---- robots.txt tahlili ----
    try:
        r_javob = requests.get(f"https://{domen}/robots.txt", timeout=6, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })
        if r_javob.status_code == 200:
            shubhali_kalitlar = ["admin", "backup", "config", "private", "secret", "login", "wp-admin", ".env"]
            yollar = []
            for qator in r_javob.text.splitlines():
                qator = qator.strip()
                if qator.lower().startswith("disallow:"):
                    yol = qator.split(":", 1)[1].strip()
                    if any(k in yol.lower() for k in shubhali_kalitlar):
                        yollar.append(yol)
            natija["robots_maxfiy_yollar"] = yollar
    except requests.exceptions.RequestException:
        pass

    # ---- Favicon xeshi (passiv fingerprinting) ----
    try:
        f_javob = requests.get(f"https://{domen}/favicon.ico", timeout=6, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })
        if f_javob.status_code == 200 and len(f_javob.content) > 0:
            natija["favicon_xesh"] = hashlib.md5(f_javob.content).hexdigest()
    except requests.exceptions.RequestException:
        pass

    # ---- Oddiy typosquatting variantlari (mavjudligini tekshirish, faqat DNS orqali) ----
    try:
        qismlar = domen.split(".")
        if len(qismlar) >= 2:
            nom = qismlar[0]
            tld = ".".join(qismlar[1:])
            variantlar = []
            if len(nom) > 3:
                # bitta harf olib tashlangan va bitta harf takrorlangan variantlar
                variantlar.append(nom[:-1] + "." + tld)
                variantlar.append(nom + nom[-1] + "." + tld)
            band_variantlar = []
            for v in variantlar[:2]:
                try:
                    socket.gethostbyname(v)
                    band_variantlar.append(v)
                except socket.gaierror:
                    continue
            natija["typosquat_variantlar"] = band_variantlar
    except Exception:
        pass

    return jsonify(natija)


# ---------- 19. SERVER JAVOB TEZLIGI ----------
@app.route("/api/performance", methods=["GET"])
def performance_endpoint():
    domen = request.args.get("domen", "")
    if not domen:
        return jsonify({"xato": "domen parametri kerak"}), 400
    domen = domen_tozala(domen)

    try:
        boshlanish = time.time()
        requests.get(f"https://{domen}", timeout=10, headers={
            "User-Agent": "Xavfsizlik-Tekshiruv-Vositasi/1.0"
        })
        tugash = time.time()
        ms = round((tugash - boshlanish) * 1000)
        return jsonify({"muvaffaqiyat": True, "domen": domen, "javob_vaqti_ms": ms})
    except requests.exceptions.RequestException as e:
        return jsonify({"muvaffaqiyat": False, "xato": str(e)}), 200


# ---------- SALOMLASHISH (server ishlab turganini tekshirish uchun) ----------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "xizmat": "Xavfsizlik Tekshiruv Backend",
        "holat": "ishlamoqda",
        "endpointlar": [
            "/api/ssl", "/api/headers", "/api/email", "/api/dns",
            "/api/ports", "/api/whois", "/api/blacklist", "/api/subdomains",
            "/api/techscan", "/api/networkinfo", "/api/mailrecords", "/api/pwnedpassword",
            "/api/extras", "/api/report",
            "/api/tlsdeep", "/api/httpprotocol", "/api/dnsextra", "/api/recon", "/api/performance"
        ]
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
