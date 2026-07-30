#!/usr/bin/env python3
"""
Xavfsizlik Tekshiruv Backend Server
Uchta xizmatni bitta API orqali taqdim etadi:
  /api/ssl?domen=...      -> SSL sertifikat tekshiruvi
  /api/headers?domen=...  -> Xavfsizlik header'lari tekshiruvi
  /api/email?email=...    -> Email sizib chiqishi tekshiruvi
"""

import ssl
import socket
import requests
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

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


# ---------- SALOMLASHISH (server ishlab turganini tekshirish uchun) ----------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "xizmat": "Xavfsizlik Tekshiruv Backend",
        "holat": "ishlamoqda",
        "endpointlar": ["/api/ssl", "/api/headers", "/api/email"]
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
