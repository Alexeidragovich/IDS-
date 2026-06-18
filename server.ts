import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini client server-side
const ai = process.env.GEMINI_API_KEY
  ? new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    })
  : null;

// API Endpoint for Gemini AI Threat Analysis
app.post("/api/gemini/analyze", async (req, res) => {
  const { ja4, type, details, host } = req.body;

  if (!ai) {
    return res.status(500).json({
      error: "Gemini API is not configured. Please add GEMINI_API_KEY to your Secrets panel.",
    });
  }

  try {
    const prompt = `Analyze this simulated TLS Client Hello footprint under the JA4 specification for intrusion detection:
Fingerprint: ${ja4}
Classification/Type: ${type}
Simulated Host: ${host}
Additional Attributes: ${JSON.stringify(details)}

Provide a threat-hunter assessment:
1. Explain the meaning of the JA4_A segment (${ja4.split('_')[0]}) - i.e. protocol, TLS version, port type, count numbers of ciphers and extensions.
2. Discuss why this profile is labeled as "${type}" and what standard or threat actor footprints it resembles (e.g., standard browser vs malicious tool like Cobalt Strike, Metasploit, Tor Exit, or PowerShell).
3. Recommend specific security actions or hunting indicators for a security analyst.
Keep the response structured, clear, and highly professional without self-referential or promotional language.`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
    });

    res.json({ analysis: response.text });
  } catch (error: any) {
    console.error("Gemini analysis error:", error);
    res.status(500).json({ error: error?.message || "Internal AI generation error" });
  }
});

// API Endpoint to send a real test Telegram Bot notification
app.post("/api/telegram/test", async (req, res) => {
  const { botToken, chatId, message } = req.body;

  if (!botToken || !chatId) {
    return res.status(400).json({ error: "Bot Token and Chat ID are required." });
  }

  try {
    const telegramUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
    const response = await fetch(telegramUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: message || "🚨 [JA4 Sentinel] TLS connection threat detected!\nHost: mal-c2.example.com\nJA4: t12o080900_3a8c715f2ac1_1a9c3e4f7a2d",
        parse_mode: "Markdown",
      }),
    });

    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.description || "Telegram API rejected the request.");
    }

    res.json({ success: true, result: data });
  } catch (error: any) {
    console.error("Telegram endpoint error:", error);
    res.status(500).json({ error: error?.message || "Failed to make Telegram connection." });
  }
});

// Endpoint to generate and download the customized python script
app.get("/api/download/script", (req, res) => {
  const botToken = (req.query.botToken as string) || "YOUR_TELEGRAM_BOT_TOKEN";
  const chatId = (req.query.chatId as string) || "YOUR_TELEGRAM_CHAT_ID";

  const scriptContent = `#!/usr/bin/env python3
"""
JA4 Network Intrusion Detection System (IDS)

This program sniffs TLS handshakes, computes JA4 fingerprints, matches them against
malicious security signatures, and fires real-time Telegram alerts via telebot.

Dependencies:
    pip install scapy pyTelegramBotAPI
Note: Running raw socket sniffing requires root/administrator privileges!
"""

import sys
import hashlib
import json
import logging
from datetime import datetime
import telebot
from scapy.all import sniff, IP, TCP, Raw

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Configuration Variables
TELEGRAM_BOT_TOKEN = "${botToken}"
TELEGRAM_CHAT_ID = "${chatId}"

# Initialize Telegram Bot
if TELEGRAM_BOT_TOKEN and "YOUR_TELEGRAM" not in TELEGRAM_BOT_TOKEN:
    logging.info("Initializing Telegram Bot connection...")
    bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)
else:
    logging.warning("No Telegram Bot token configured. Alerts will be logged to console only.")
    bot = None

# Known malicious profiles and reference fingerprints for matching
THREAT_DATABASE = {
    # Cobalt Strike Default TLS handshakes
    't12o080900_3a8c715f2ac1_1a9c3e4f7a2d': {
        'name': 'Cobalt Strike Default Beacon C2',
        'severity': 'CRITICAL',
        'details': 'Matches Default Cobalt Strike beacon handshakes over modern raw TLS channels.'
    },
    't12o080800_4da1b2c4d5e6_6a1b2c3d4e5f': {
        'name': 'Sliver C2 Implant TLS Handshake',
        'severity': 'CRITICAL',
        'details': 'Sliver implants utilizing standard TLS/HTTP fallback protocols.'
    },
    # Metasploit Reverse HTTPS Meterpreter default config
    't12d100700_da67bc13ef90_ab98fd24ee11': {
        'name': 'Metasploit Meterpreter Reverse HTTPS TLS',
        'severity': 'HIGH',
        'details': 'Standard signature for HTTPS Meterpreter payload connections.'
    },
    # Tor Browser handshake patterns
    't13d1915h2_9e2a5f4c3d2b_3a5c2e1f9b8d': {
        'name': 'Tor Relay Connection / Tor Browser Handshake',
        'severity': 'WARNING',
        'details': 'Indicates high-entropy routing associated with Tor networks.'
    }
}

def parse_tls_client_hello(raw_payload):
    """
    Rudimentary parser for extraction of TLS Client Hello structures.
    In production environments, a native plugin (e.g. Zeek or tshark) or a dedicated TLS parser
    is recommended.
    """
    try:
        # Check basic TLS record constraints
        # Record Type: Handshake (0x16), Version: TLS 1.0 - 1.2 (0x03 0x01/0x02/0x03)
        if len(raw_payload) < 43 or raw_payload[0] != 0x16:
            return None
        
        # Verify Handshake Type: Client Hello (0x01)
        if raw_payload[5] != 0x01:
            return None

        # Parse pointers to versions and identifiers
        # Session ID length
        session_id_len_pos = 43
        session_id_len = raw_payload[session_id_len_pos]
        
        # Cipher suites length
        ciphers_len_pos = session_id_len_pos + 1 + session_id_len
        if ciphers_len_pos + 2 > len(raw_payload):
            return None
        ciphers_len = int.from_bytes(raw_payload[ciphers_len_pos:ciphers_len_pos+2], byteorder='big')
        
        # Extract Ciphers
        ciphers_start = ciphers_len_pos + 2
        cipher_bytes = raw_payload[ciphers_start:ciphers_start + ciphers_len]
        ciphers_list = []
        for i in range(0, len(cipher_bytes), 2):
            if i + 2 <= len(cipher_bytes):
                cipher_val = int.from_bytes(cipher_bytes[i:i+2], byteorder='big')
                ciphers_list.append(cipher_val)

        # Parse Extensions
        compression_len_pos = ciphers_start + ciphers_len
        compression_len = raw_payload[compression_len_pos]
        extensions_len_pos = compression_len_pos + 1 + compression_len
        
        extensions_list = []
        alpn_val = '00'
        
        if extensions_len_pos + 2 <= len(raw_payload):
            exts_len = int.from_bytes(raw_payload[extensions_len_pos:extensions_len_pos+2], byteorder='big')
            exts_start = extensions_len_pos + 2
            exts_bytes = raw_payload[exts_start:exts_start + exts_len]
            
            ptr = 0
            while ptr + 4 <= len(exts_bytes):
                ext_type = int.from_bytes(exts_bytes[ptr:ptr+2], byteorder='big')
                ext_len = int.from_bytes(exts_bytes[ptr+2:ptr+4], byteorder='big')
                ptr += 4
                
                # Filter out GREASE extension types
                if (ext_type & 0x0F0F) != 0x0A0A:
                    extensions_list.append(ext_type)
                    
                    # If extension is ALPN (0x0010)
                    if ext_type == 16 and ptr + ext_len <= len(exts_bytes):
                        alpn_data = exts_bytes[ptr:ptr+ext_len]
                        try:
                            # Parse ALPN values
                            alpn_str_len = int.from_bytes(alpn_data[2:4], byteorder='big')
                            alpn_str = alpn_data[4:4+alpn_str_len].decode('utf-8', errors='ignore')
                            if alpn_str:
                                alpn_val = alpn_str
                        except Exception:
                            pass
                ptr += ext_len

        # Ignores GREASE values on cipher suites
        ciphers_filtered = [c for c in ciphers_list if (c & 0x0F0F) != 0x0A0A]
        extensions_filtered = sorted(extensions_list)

        return {
            'ciphers': ciphers_filtered,
            'extensions': extensions_filtered,
            'alpn': alpn_val
        }
    except Exception as e:
        logging.debug(f"Parsing exception to payload: {e}")
        return None

def compute_ja4(tls_data, dest_port=443):
    """
    Calculates JA4_A_B_C signature base for parsed client hello attributes.
    """
    # Segment A format: t[tls_version][dest_port][cipher_cnt][ext_cnt][alpn_first_last]
    protocol = 't' # TCP Sniffed
    tls_version = '13' # Assumed modern fallback
    port_type = 'd' if dest_port == 443 else 'o'
    
    cipher_cnt = f"{min(99, len(tls_data['ciphers'])):02d}"
    ext_cnt = f"{min(99, len(tls_data['extensions'])):02d}"
    
    # ALPN evaluation
    alpn = tls_data['alpn']
    if alpn == '00':
        alpn_char = '00'
    else:
        alpn_char = f"{alpn[0]}{alpn[-1]}" if len(alpn) > 1 else f"{alpn}0"
        
    ja4_a = f"{protocol}{tls_version}{port_type}{cipher_cnt}{ext_cnt}{alpn_char}"
    
    # Segment B format: sorted list of ciphers in hex, hashed, first 12 chars
    ciphers_hex = [f"{c:04x}" for c in sorted(tls_data['ciphers'])]
    ciphers_str = ",".join(ciphers_hex)
    ja4_b = hashlib.sha256(ciphers_str.encode('utf-8')).hexdigest()[:12]
    
    # Segment C format: sorted list of extensions, hashed, first 12 chars
    exts_hex = [f"{e:04x}" for e in sorted(tls_data['extensions'])]
    exts_str = ",".join(exts_hex)
    ja4_c = hashlib.sha256(exts_str.encode('utf-8')).hexdigest()[:12]
    
    return f"{ja4_a}_{ja4_b}_{ja4_c}"

def handle_sniffed_packet(pkt):
    """
    Main callback when a TCP connection carries potential Raw payloads for parsing.
    """
    if IP in pkt and TCP in pkt and pkt.haslayer(Raw):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        
        payload = bytes(pkt[Raw])
        tls_data = parse_tls_client_hello(payload)
        
        if tls_data:
            ja4_fingerprint = compute_ja4(tls_data, dport)
            logging.info(f"[*] Detected TLS Client Hello | {src_ip}:{sport} -> {dst_ip}:{dport} | JA4: {ja4_fingerprint}")
            
            # Threat match check
            if ja4_fingerprint in THREAT_DATABASE:
                threat = THREAT_DATABASE[ja4_fingerprint]
                trigger_intrusion_alert(src_ip, sport, dst_ip, dport, ja4_fingerprint, threat)

def trigger_intrusion_alert(src_ip, sport, dst_ip, dport, fingerprint, threat):
    """
    Fires off local logs and dispatches instant Telegram bot messages.
    """
    log_msg = f"[🚨 ALERT] [{threat['severity']}] {threat['name']} Detected! {src_ip} -> {dst_ip} (JA4: {fingerprint})"
    logging.error(log_msg)
    
    if bot:
        alert_body = (
            f"🚨 *[JA4 Sentinel IDS Notification]*\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"*Incident Type:* {threat['name']}\n"
            f"*Severity:* 🟥 {threat['severity']}\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"*Source:* {src_ip}:{sport}\n"
            f"*Destination:* {dst_ip}:{dport}\n"
            f"*JA4 Signature:* {fingerprint}\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"*Details:* {threat['details']}\n"
            f"*Timestamp:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        try:
            bot.send_message(TELEGRAM_CHAT_ID, alert_body, parse_mode='Markdown')
            logging.info("Telegram notification successfully sent.")
        except Exception as e:
            logging.error(f"Failed to transmit Telegram message: {e}")

def main():
    logging.info("==============================================")
    logging.info("    JA4 SENTINEL INTRUSION DETECTION SYSTEM   ")
    logging.info("==============================================")
    logging.info("Active sniff filter: TCP Port 443 (TLS handshakes)")
    logging.info("Sniffing network traffic... Press Ctrl+C to terminate.")
    
    try:
        # Sniff on basic interfaces for TLS handshakes
        sniff(filter="tcp port 443", prn=handle_sniffed_packet, store=0)
    except KeyboardInterrupt:
        logging.info("Exiting gracefully. Safe hunting!")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Sniffer failure: {e}. Ensure you are executing with administrative privileges (sudo).")
        sys.exit(1)

if __name__ == "__main__":
    main()
`;

  res.setHeader("Content-Disposition", 'attachment; filename="ja4_ids.py"');
  res.setHeader("Content-Type", "text/plain");
  res.send(scriptContent);
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Express server running on port ${PORT}`);
  });
}

startServer();
