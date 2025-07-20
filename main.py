import os
import re
import discord
import requests
import asyncio
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
intents = discord.Intents.all()  # Cambiado de default() a all()
client = discord.Client(intents=intents)

# Servidor Flask para mantener activo en Render
app = Flask(__name__)
@app.route("/")
def home():
    return "✅ Bot activo y funcionando."

def run_flask():
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)

Thread(target=run_flask).start()

@client.event
async def on_ready():
    print(f"✅ Bot iniciado como {client.user}")

# === FUNCIONES DE ESCANEO ===

def scan_file_metadefender(filename, file_bytes):
    try:
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
    except Exception as e:
        print(f"❌ Error en MetaDefender File: {e}")
    return None

def scan_file_hybrid_analysis(filename, file_bytes):
    try:
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
            sha256 = response.json().get("sha256")
            print(f"Archivo subido a Hybrid Analysis, SHA256: {sha256}")
            return {
                "report_url": f"https://www.hybrid-analysis.com/sample/{sha256}",
                "malicious": True
            }
        print(f"Error Hybrid Analysis archivo: {response.status_code}")
    except Exception as e:
        print(f"❌ Error en HybridAnalysis File: {e}")
    return None

def scan_url_metadefender(url_to_scan):
    try:
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
    except Exception as e:
        print(f"❌ Error en MetaDefender URL: {e}")
    return None

def scan_url_hybrid_analysis(url_to_scan):
    try:
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
                "malicious": True
            }
        print(f"Error Hybrid Analysis URL: {response.status_code}")
    except Exception as e:
        print(f"❌ Error en HybridAnalysis URL: {e}")
    return None

def extract_urls(text):
    url_regex = r"https?://[^\s]+"
    return re.findall(url_regex, text)

# === EVENTO PRINCIPAL ===

@client.event
async def on_message(message):
    print("✅ on_message ACTIVADO")
    try:
        print(f"📥 Mensaje recibido: {message.content} de {message.author}")

        if message.author == client.user:
            return

        alert_channel = client.get_channel(ALERT_CHANNEL_ID)
        if alert_channel is None:
            print("❌ No se pudo obtener el canal de alertas.")
            return
        else:
            print(f"📢 Canal de alertas encontrado: {alert_channel.name}")

        contenido_malicioso = False

        # Escaneo de URLs
        urls = extract_urls(message.content)
        for url in urls:
            print(f"🌐 Analizando URL: {url}")
            result = await asyncio.to_thread(scan_url_metadefender, url)
            if not result:
                result = await asyncio.to_thread(scan_url_hybrid_analysis, url)

            if result and result["malicious"]:
                contenido_malicioso = True
                await alert_channel.send(
                    f"🚨 **ALERTA DE URL MALICIOSA**\n👤 Usuario: {message.author.mention}\n🌐 URL: {url}\n🔎 Reporte: {result['report_url']}"
                )

        # Escaneo de archivos
        for attachment in message.attachments:
            filename = attachment.filename
            print(f"📁 Analizando archivo: {filename}")
            file_bytes = await attachment.read()
            result = await asyncio.to_thread(scan_file_metadefender, filename, file_bytes)
            if not result:
                result = await asyncio.to_thread(scan_file_hybrid_analysis, filename, file_bytes)

            if result and result["malicious"]:
                contenido_malicioso = True
                await alert_channel.send(
                    f"🚨 **ARCHIVO MALICIOSO DETECTADO**\n👤 Usuario: {message.author.mention}\n📂 Archivo: `{filename}`\n🔎 Reporte: {result['report_url']}"
                )

        # Eliminar mensaje malicioso
        if contenido_malicioso:
            try:
                await message.delete()
                print(f"🗑️ Mensaje borrado: {message.id}")
            except discord.Forbidden:
                print("⚠️ No tengo permisos para borrar mensajes.")
            except discord.HTTPException as e:
                print(f"❌ Error al borrar el mensaje: {e}")

    except Exception as error:
        print(f"❌ Error en on_message: {error}")

# === INICIAR EL BOT ===
print(f"Token leído: {TOKEN[:5]}...")
client.run(TOKEN)
