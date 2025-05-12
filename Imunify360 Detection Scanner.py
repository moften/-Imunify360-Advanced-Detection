import requests
import time
from datetime import datetime

def banner():
    print("==============================================")
    print("     Imunify360 Advanced Detection v3.0        ")
    print("  Busca paneles expuestos y analiza respuestas ")
    print("               by m10sec (2025)                ")
    print("==============================================\n")

payloads = [
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "?a[]=1",
    "?cmd=ls",
    "?id=%3Cscript%3E",
    "?exec=/bin/bash",
    "?base64=ZWNobyAiaGFja2VkIg==",
]

imunify_paths = [
    "/imunify360/",
    "/cgi-sys/defaultwebpage.cgi",
    "/cgi/im360/",
    "/cgi-sys/autoconfig.cgi",
    "/vendor/imunify360/",
    "/.well-known/imunify-preload",
    "/im360/",
    "/~root/",
]

logfile = "imunify360_advanced_results.log"

def enviar_request(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (PentestScanner by m10sec)"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        return response
    except requests.exceptions.RequestException as e:
        log = f"[!] Error de conexión en {url}: {e}\n"
        guardar_log(log)
        print(log)
        return None

def analizar_respuesta(url, response, origen):
    if not response:
        return

    body = response.text.lower()
    headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
    status = response.status_code

    log_entry = f"=== {origen} ===\n"
    log_entry += f"URL: {url}\n"
    log_entry += f"Status Code: {status}\n"
    log_entry += f"Headers:\n{headers}\n"
    log_entry += "Body (primeros 500 caracteres):\n"
    log_entry += body[:500] + "\n"
    log_entry += "-" * 60 + "\n"
    guardar_log(log_entry)

    if "imunify360" in headers.lower() or "imunify360" in body:
        print(f"[+] {origen}: detección directa de Imunify360 en {url}")
    elif "access denied" in body and "web protection" in body:
        print(f"[+] {origen}: mensaje típico de bloqueo de Imunify360 en {url}")
    elif "/cgi-sys/defaultwebpage.cgi" in response.url:
        print(f"[+] {origen}: redirección al default page – probable protección activa.")
    elif "cpanel" in headers.lower() or "whm" in body:
        print(f"[!] {origen}: posible entorno con cPanel/WHM en {url}")
    elif status in [403, 406]:
        print(f"[!] {origen}: código sospechoso {status} en {url}")
    elif "traceback" in body or "exception" in body:
        print(f"[!] {origen}: posible traza de error en {url}")

def guardar_log(entry):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(f"{timestamp}\n{entry}\n")

def detectar_imunify(url_base):
    print(f"[*] Escaneando payloads en: {url_base}\n")
    for payload in payloads:
        print(f"[*] Payload: {payload}")
        full_url = f"{url_base}/{payload}" if not payload.startswith("?") else f"{url_base}{payload}"
        resp = enviar_request(full_url)
        analizar_respuesta(full_url, resp, "Payload")
        time.sleep(1.5)

    print(f"\n[*] Escaneando rutas comunes relacionadas a Imunify360 y cPanel...")
    for path in imunify_paths:
        full_url = f"{url_base}{path}"
        print(f"[*] Verificando ruta: {full_url}")
        resp = enviar_request(full_url)
        analizar_respuesta(full_url, resp, "Ruta común")
        time.sleep(1.5)

    print(f"\n[*] Escaneo finalizado. Resultados en: {logfile}")
    print("[*] Si hay redirecciones, 403s masivos o menciones a Imunify, es señal de su presencia.")

if __name__ == "__main__":
    banner()
    url = input("Ingresa la URL base (ej: https://objetivo.com): ").strip().rstrip('/')
    if not url.startswith("http"):
        url = "http://" + url
    detectar_imunify(url)