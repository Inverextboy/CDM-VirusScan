import os
import re
import discord
import requests
from flask import Flask
from threading import Thread
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()
TOKEN = os.getenv("TOKEN")
METADEFENDER_API_KEY = os.getenv("METADEFENDER_API_KEY")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
ALERT_CHANNEL_ID = int(os.getenv("ALERT_CHANNEL_ID"))

# Configurar el bot
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)

# Servidor web para Render
app = Flask(__name__)
@app.route("/")
def home():
    return "Bot activo"
def run_flask():
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
Thread(target=run_flask).start()

@client.event
async def on_ready():
    print(f"✅ Bot iniciado como {client.user}")

# === FUNCIONES DE ESCANEO DE ARCHIVOS ===

def scan_file_metadefender(filename, file_bytes):
    print(f"🔍 Escaneando archivo en MetaDefender: {filename}")
    url = "https://api.metadefender.com/v4/file"
    headers = {
        "apikey": METADEFENDER_API_KEY,
        "Content-Type": "application/octet-stream",
        "filename": filename
    }
    response = requests.post(url, headers=headers, data=file_bytes)
    if response.status_code == 200:
        data = response.json()
        data_id = data["data_id"]
        result = data.get("scan_results", {}).get("scan_all_result_a", "").lower()
        is_malicious = result == "infected"
        print(f"Resultado MetaDefender archivo: {result}")
        return {
            "report_url": f"https://metadefender.opswat.com/results/file/{data_id}",
            "malicious": is_malicious
        }
    print(f"Error MetaDefender archivo: {response.status_code}")
    return None

def scan_file_hybrid_analysis(filename, file_bytes):
    print(f"🔍 Escaneando archivo en Hybrid Analysis: {filename}")
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "Falcon Sandbox"
    }
    files = { "file": (filename, file_bytes) }
    data = { "environment_id": "300" }

    response = requests.post(url, headers=headers, files=files, data=data)
    if response.status_code == 200:
        sha256 = response.json()["sha256"]
        print(f"Archivo subido a Hybrid Analysis, SHA256: {sha256}")
        return {
            "report_url": f"https://www.hybrid-analysis.com/sample/{sha256}",
            "malicious": True  # Se asume malicioso si se sube
        }
    print(f"Error Hybrid Analysis archivo: {response.status_code}")
    return None

# === FUNCIONES DE ESCANEO DE URLS ===

def scan_url_metadefender(url_to_scan):
    print(f"🔍 Escaneando URL en MetaDefender: {url_to_scan}")
    url = "https://api.metadefender.com/v4/url"
    headers = {
        "apikey": METADEFENDER_API_KEY,
        "Content-Type": "application/json"
    }
    json_data = { "url": url_to_scan }

    response = requests.post(url, headers=headers, json=json_data)
    if response.status_code == 200:
        data = response.json()
        data_id = data["data_id"]
        result = data.get("scan_results", {}).get("scan_all_result_a", "").lower()
        is_malicious = result == "infected"
        print(f"Resultado MetaDefender URL: {result}")
        return {
            "report_url": f"https://metadefender.opswat.com/results/url/{data_id}",
            "malicious": is_malicious
        }
    print(f"Error MetaDefender URL: {response.status_code}")
    return None

def scan_url_hybrid_analysis(url_to_scan):
    print(f"🔍 Escaneando URL en Hybrid Analysis: {url_to_scan}")
    url = "https://www.hybrid-analysis.com/api/v2/quick-scan/url"
    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "Content-Type": "application/json"
    }
    json_data = {
        "url": url_to_scan,
        "environment_id": "300"
    }

    response = requests.post(url, headers=headers, json=json_data)
    if response.status_code == 200:
        job_id = response.json().get("job_id")
        print(f"URL enviada a Hybrid Analysis, job_id: {job_id}")
        return {
            "report_url": f"https://www.hybrid-analysis.com/scan-result/{job_id}",
            "malicious": True  # Se asume malicioso
        }
    print(f"Error Hybrid Analysis URL: {response.status_code}")
    return None

# === EXTRACCIÓN DE URLS DEL MENSAJE ===

def extract_urls(text):
    url_regex = r"https?://[^\s]+"
    return re.findall(url_regex, text)

# === EVENTO PRINCIPAL ===

@client.event
async def on_message(message):
    print(f"📥 Mensaje recibido: {message.content} de {message.author}")

    if message.author == client.user:
        return

    alert_channel = client.get_channel(ALERT_CHANNEL_ID)
    print(f"🔔 Canal de alertas obtenido: {alert_channel}")
    if alert_channel is None:
        print("❌ No se pudo obtener el canal de alertas.")
        return
    contenido_malicioso = False

    # Analizar URLs
    urls = extract_urls(message.content)
    for url in urls:
        print(f"🌐 Analizando URL: {url}")
        result = scan_url_metadefender(url)
        if not result:
            result = scan_url_hybrid_analysis(url)

        if result and result["malicious"]:
            contenido_malicioso = True
            await alert_channel.send(
                f"🚨 **ALERTA DE URL MALICIOSA**\n👤 Usuario: {message.author.mention}\n🌐 URL: {url}\n🔎 Reporte: {result['report_url']}"
            )

    # Analizar archivos
    for attachment in message.attachments:
        print(f"📁 Analizando archivo: {attachment.filename}")
        filename = attachment.filename
        file_bytes = await attachment.read()

        result = scan_file_metadefender(filename, file_bytes)
        if not result:
            result = scan_file_hybrid_analysis(filename, file_bytes)

        if result and result["malicious"]:
            contenido_malicioso = True
            await alert_channel.send(
                f"🚨 **ARCHIVO MALICIOSO DETECTADO**\n👤 Usuario: {message.author.mention}\n📂 Archivo: `{filename}`\n🔎 Reporte: {result['report_url']}"
            )

    if contenido_malicioso:
        try:
            await message.delete()
            print(f"🗑️ Mensaje borrado: {message.id}")
        except discord.Forbidden:
            print("⚠️ No tengo permisos para borrar mensajes.")
        except discord.HTTPException as e:
            print(f"❌ Error al borrar el mensaje: {e}")

# === INICIAR EL BOT ===

client.run(TOKEN)
