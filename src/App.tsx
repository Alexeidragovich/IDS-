import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Activity,
  Send,
  Download,
  Terminal,
  FileCode,
  Settings,
  HelpCircle,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Plus,
  Play,
  Upload,
  Cpu,
  CornerDownRight,
  Database,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Info
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

// Interfaces
interface Packet {
  id: string;
  timestamp: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  sni: string;
  ja4: string;
  type: "Safe" | "Warning" | "Critical";
  tool: string;
  details: {
    tlsVersion: string;
    protocol: string;
    ciphersCount: number;
    extensionsCount: number;
    alpn: string;
    ciphersList: string[];
    extensionsList: string[];
  };
}

interface AlertLog {
  id: string;
  timestamp: string;
  botToken: string;
  chatId: string;
  threatName: string;
  fingerprint: string;
  status: "success" | "failed";
  message: string;
}

// Initial Mock Traffic Data - High-Fidelity Cyber Sec patterns
const INITIAL_PACKETS: Packet[] = [
  {
    id: "pkt_1",
    timestamp: "2026-06-18 14:01:05",
    srcIp: "192.168.1.42",
    srcPort: 54102,
    dstIp: "142.250.190.46", // Google
    dstPort: 443,
    sni: "www.google.com",
    ja4: "t13d1512h2_8b5a3d7f9ec3_5a2c4b7d1e0f",
    type: "Safe",
    tool: "Chrome Browser (v120)",
    details: {
      tlsVersion: "1.3",
      protocol: "TCP",
      ciphersCount: 15,
      extensionsCount: 12,
      alpn: "h2",
      ciphersList: ["0x1301 (TLS_AES_128_GCM_SHA256)", "0x1302 (TLS_AES_256_GCM_SHA384)", "0x1303 (TLS_CHACHA20_POLY1305_SHA256)", "0xc02b (ECDHE-ECDSA-AES128-GCM-SHA256)", "0xc02f (ECDHE-RSA-AES128-GCM-SHA256)"],
      extensionsList: ["server_name (0x0000)", "supported_groups (0x000a)", "key_share (0x0033)", "supported_versions (0x002b)", "application_layer_protocol_negotiation (0x0010)"]
    }
  },
  {
    id: "pkt_2",
    timestamp: "2026-06-18 14:01:12",
    srcIp: "192.168.1.109",
    srcPort: 49231,
    dstIp: "185.190.140.12", // Known malicious C2 node
    dstPort: 443,
    sni: "secure-update-cloud.org",
    ja4: "t12o080900_3a8c715f2ac1_1a9c3e4f7a2d",
    type: "Critical",
    tool: "Cobalt Strike Beacon C2",
    details: {
      tlsVersion: "1.2",
      protocol: "TCP",
      ciphersCount: 8,
      extensionsCount: 9,
      alpn: "None (Raw Client TLS)",
      ciphersList: ["0xc02f (ECDHE-RSA-AES128-GCM-SHA256)", "0xc030 (ECDHE-RSA-AES256-GCM-SHA384)", "0xc013 (ECDHE-RSA-AES128-SHA)", "0xc014 (ECDHE-RSA-AES256-SHA)", "0x009c (RSA-AES128-GCM-SHA256)"],
      extensionsList: ["server_name (0x0000)", "elliptic_curves (0x000a)", "ec_point_formats (0x000b)", "signature_algorithms (0x000d)", "renegotiation_info (0xff01)"]
    }
  },
  {
    id: "pkt_3",
    timestamp: "2026-06-18 14:01:21",
    srcIp: "192.168.1.42",
    srcPort: 54108,
    dstIp: "109.105.109.109", // Tor Exit Relay
    dstPort: 443,
    sni: "tor-relay-exit-5.relay.net",
    ja4: "t13d1915h2_9e2a5f4c3d2b_3a5c2e1f9b8d",
    type: "Warning",
    tool: "Tor Browser Handshake",
    details: {
      tlsVersion: "1.3",
      protocol: "TCP",
      ciphersCount: 19,
      extensionsCount: 15,
      alpn: "http/1.1",
      ciphersList: ["0x1301 (TLS_AES_128_GCM_SHA256)", "0x1302 (TLS_AES_256_GCM_SHA384)", "0xc02b (ECDHE-ECDSA-AES128-GCM-SHA256)", "0xc02c (ECDHE-ECDSA-AES256-GCM-SHA384)", "0x009d (RSA-AES256-GCM-SHA384)"],
      extensionsList: ["server_name (0x0000)", "supported_groups (0x000a)", "key_share (0x0033)", "supported_versions (0x002b)", "signature_algorithms (0x000d)", "application_layer_protocol_negotiation (0x0010)"]
    }
  },
  {
    id: "pkt_4",
    timestamp: "2026-06-18 14:01:38",
    srcIp: "192.168.1.15",
    srcPort: 38241,
    dstIp: "149.154.167.220", // Telegram API
    dstPort: 443,
    sni: "api.telegram.org",
    ja4: "t12d050500_de56bc34ee21_bc98fe12aa09",
    type: "Safe",
    tool: "Python Bot Agent API Connection",
    details: {
      tlsVersion: "1.2",
      protocol: "TCP",
      ciphersCount: 5,
      extensionsCount: 5,
      alpn: "None",
      ciphersList: ["0xc02c (ECDHE-ECDSA-AES256-GCM-SHA384)", "0xc02b (ECDHE-ECDSA-AES128-GCM-SHA256)", "0xc030 (ECDHE-RSA-AES256-GCM-SHA384)"],
      extensionsList: ["server_name (0x0000)", "ec_point_formats (0x000b)", "supported_groups (0x000a)", "signature_algorithms (0x000d)"]
    }
  },
  {
    id: "pkt_5",
    timestamp: "2026-06-18 14:01:50",
    srcIp: "192.168.1.180",
    srcPort: 41249,
    dstIp: "172.56.230.14", // Suspicious payload retrieval server
    dstPort: 443,
    sni: "malware-delivery-cdn.com",
    ja4: "t12d100700_da67bc13ef90_ab98fd24ee11",
    type: "Critical",
    tool: "Metasploit Core Meterpreter payload",
    details: {
      tlsVersion: "1.2",
      protocol: "TCP",
      ciphersCount: 10,
      extensionsCount: 7,
      alpn: "None",
      ciphersList: ["0xc013 (ECDHE-RSA-AES128-SHA)", "0xc014 (ECDHE-RSA-AES256-SHA)", "0x002f (RSA-AES128-SHA)", "0x0035 (RSA-AES256-SHA)"],
      extensionsList: ["server_name (0x0000)", "supported_groups (0x000a)", "ec_point_formats (0x000b)", "signature_algorithms (0x000d)"]
    }
  }
];

// Reference threat database table for displays
const REFERENCE_THREATS = [
  { ja4: "t12o080900_3a8c715f2ac1_1a9c3e4f7a2d", name: "Cobalt Strike C2 Beacon Default Handshake", severity: "Critical", matchDetails: "Matches Cobalt Strike's default configuration TLS handshake structure, indicating potentially breached C2 connectivity." },
  { ja4: "t12d100700_da67bc13ef90_ab98fd24ee11", name: "Metasploit Reverse HTTPS Meterpreter Payload", severity: "Critical", matchDetails: "A signature profile matching standard Metasploit payload engines executing HTTPS reverse shell handshakes." },
  { ja4: "t13d1915h2_9e2a5f4c3d2b_3a5c2e1f9b8d", name: "Tor Browser Exit Route Entry", severity: "Warning", matchDetails: "Matches Firefox/Tor fingerprints bypassing local DNS endpoints for dark-routing relay connections." },
  { ja4: "t12o080800_4da1b2c4d5e6_6a1b2c3d4e5f", name: "Sliver C2 Implant Fallback Handshake", severity: "Critical", matchDetails: "Consistent signature matching Go-based Sliver Implants conducting raw HTTPS handshakes." }
];

export default function App() {
  const [activeMenu, setActiveMenu] = useState<"console" | "config" | "exporter" | "lab">("console");
  const [packets, setPackets] = useState<Packet[]>(INITIAL_PACKETS);
  const [selectedPacket, setSelectedPacket] = useState<Packet>(INITIAL_PACKETS[1]); // CS Beacon highlighted
  
  // Telegram Form States
  const [botToken, setBotToken] = useState<string>(() => localStorage.getItem("ja4_bot_token") || "");
  const [chatId, setChatId] = useState<string>(() => localStorage.getItem("ja4_chat_id") || "");
  const [isSendingAlert, setIsSendingAlert] = useState(false);
  const [alertLogs, setAlertLogs] = useState<AlertLog[]>([]);
  const [alertSuccess, setAlertSuccess] = useState<string | null>(null);
  const [alertError, setAlertError] = useState<string | null>(null);

  // Gemini Analyzer State
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  // Simulation sniffer state
  const [isLiveSniffing, setIsLiveSniffing] = useState(true);
  const [processedCount, setProcessedCount] = useState(5524);

  // Lab State (JA4 Custom Decoder)
  const [labProto, setLabProto] = useState("t");
  const [labVer, setLabVer] = useState("13");
  const [labPort, setLabPort] = useState("d");
  const [labCiphersVal, setLabCiphersVal] = useState("0x1301,0x1302,0xc02b,0xc030");
  const [labExtensionsVal, setLabExtensionsVal] = useState("0x0000,0x000a,0x0033,0x002b");
  const [labAlpn, setLabAlpn] = useState("h2");
  const [calculatedLabJa4, setCalculatedLabJa4] = useState("");

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-save Telegram Token
  useEffect(() => {
    localStorage.setItem("ja4_bot_token", botToken);
  }, [botToken]);

  useEffect(() => {
    localStorage.setItem("ja4_chat_id", chatId);
  }, [chatId]);

  // Generate a random simulated handshake packet occasionally if live sniffing is active
  useEffect(() => {
    if (!isLiveSniffing) return;

    const interval = setInterval(() => {
      // 10% chance of threat, 90% chance of safe packet
      const isThreat = Math.random() < 0.15;
      const isTor = Math.random() < 0.08;
      
      const ipOctet = () => Math.floor(Math.random() * 254) + 1;
      const srcPort = Math.floor(Math.random() * 16000) + 49152;
      const id = "pkt_" + Math.random().toString(36).substr(2, 9);
      const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);

      let newPacket: Packet;

      if (isThreat) {
        const matchingC2Type = Math.random() > 0.5 ? "Cobalt" : "Metasploit";
        if (matchingC2Type === "Cobalt") {
          newPacket = {
            id,
            timestamp,
            srcIp: `192.168.1.${ipOctet()}`,
            srcPort,
            dstIp: `${ipOctet()}.${ipOctet()}.${ipOctet()}.${ipOctet()}`,
            dstPort: 443,
            sni: "cloud-update-system.net",
            ja4: "t12o080900_3a8c715f2ac1_1a9c3e4f7a2d",
            type: "Critical",
            tool: "Cobalt Strike Beacon C2",
            details: {
              tlsVersion: "1.2",
              protocol: "TCP",
              ciphersCount: 8,
              extensionsCount: 9,
              alpn: "None (Raw Client TLS)",
              ciphersList: ["0xc02f (ECDHE-RSA-AES128-GCM-SHA256)", "0xc030 (ECDHE-RSA-AES256-GCM-SHA384)", "0xc013 (ECDHE-RSA-AES128-SHA)"],
              extensionsList: ["server_name (0x0000)", "elliptic_curves (0x000a)", "signature_algorithms (0x000d)"]
            }
          };
        } else {
          newPacket = {
            id,
            timestamp,
            srcIp: `192.168.1.${ipOctet()}`,
            srcPort,
            dstIp: `${ipOctet()}.${ipOctet()}.${ipOctet()}.${ipOctet()}`,
            dstPort: 443,
            sni: "malware-retrieval.com",
            ja4: "t12d100700_da67bc13ef90_ab98fd24ee11",
            type: "Critical",
            tool: "Metasploit Meterpreter Reverse HTTPS",
            details: {
              tlsVersion: "1.2",
              protocol: "TCP",
              ciphersCount: 10,
              extensionsCount: 7,
              alpn: "None",
              ciphersList: ["0xc013 (ECDHE-RSA-AES128-SHA)", "0xc014 (ECDHE-RSA-AES256-SHA)", "0x002f (RSA-AES128-SHA)"],
              extensionsList: ["server_name (0x0000)", "supported_groups (0x000a)", "ec_point_formats (0x000b)"]
            }
          };
        }
      } else if (isTor) {
        newPacket = {
          id,
          timestamp,
          srcIp: `192.168.1.${ipOctet()}`,
          srcPort,
          dstIp: `${ipOctet()}.${ipOctet()}.${ipOctet()}.${ipOctet()}`,
          dstPort: 443,
          sni: "onion-routing-node.org",
          ja4: "t13d1915h2_9e2a5f4c3d2b_3a5c2e1f9b8d",
          type: "Warning",
          tool: "Tor Browser TLS Handshake",
          details: {
            tlsVersion: "1.3",
            protocol: "TCP",
            ciphersCount: 19,
            extensionsCount: 15,
            alpn: "http/1.1",
            ciphersList: ["0x1301 (TLS_AES_128_GCM_SHA256)", "0x1302 (TLS_AES_256_GCM_SHA384)", "0xc02b (ECDHE-ECDSA-AES128-GCM-SHA256)"],
            extensionsList: ["server_name (0x0000)", "supported_groups (0x000a)", "key_share (0x0033)"]
          }
        };
      } else {
        const platforms = [
          { tool: "Chrome Browser (v122)", sni: "api.github.com", ja4: "t13d1512h2_8b5a3d7f9ec3_5a2c4b7d1e0f", alpn: "h2", ciphers: 15 },
          { tool: "Firefox Browser", sni: "wikipedia.org", ja4: "t13d1715h2_8a2d3f7e9bc1_4c3a2b1f0e9d", alpn: "h2", ciphers: 17 },
          { tool: "macOS Safari", sni: "apple.com", ja4: "t13d1410h2_6a4e3d5f2ec3_3a2d4c6d8e0f", alpn: "h2", ciphers: 14 },
          { tool: "Curl Request client", sni: "api.weather.com", ja4: "t12d080600_1a4b5d6f3e0c_8b3a7f2e1c0d", alpn: "None", ciphers: 8 }
        ];
        const choice = platforms[Math.floor(Math.random() * platforms.length)];
        newPacket = {
          id,
          timestamp,
          srcIp: `192.168.1.${ipOctet()}`,
          srcPort,
          dstIp: `${ipOctet()}.${ipOctet()}.${ipOctet()}.${ipOctet()}`,
          dstPort: 443,
          sni: choice.sni,
          ja4: choice.ja4,
          type: "Safe",
          tool: choice.tool,
          details: {
            tlsVersion: choice.tool.includes("v122") || choice.tool.includes("Firefox") || choice.tool.includes("Safari") ? "1.3" : "1.2",
            protocol: "TCP",
            ciphersCount: choice.ciphers,
            extensionsCount: 10 + Math.floor(Math.random() * 4),
            alpn: choice.alpn,
            ciphersList: ["0x1301 (TLS_AES_128_GCM_SHA256)", "0x1302 (TLS_AES_256_GCM_SHA384)"],
            extensionsList: ["server_name (0x0000)", "supported_groups (0x000a)", "key_share (0x0033)"]
          }
        };
      }

      setPackets(prev => [newPacket, ...prev.slice(0, 24)]);
      setProcessedCount(prev => prev + 1);

      // If the newly simulated packet is Critical/Threat, match user Telegram configuration to auto-trigger mock/real alerts!
      if (newPacket.type === "Critical" && botToken && chatId) {
        dispatchSlackTelegramAlert(newPacket);
      }

    }, 6000);

    return () => clearInterval(interval);
  }, [isLiveSniffing, botToken, chatId]);

  // Handle calculating Custom JA4 Lab fingerprint from selections
  useEffect(() => {
    try {
      // Dummy hashing logic to simulate actual robust SHA256 truncations client-side dynamically
      const cleanCiphers = labCiphersVal
        .split(",")
        .map(x => x.trim().toLowerCase())
        .filter(x => x.length > 0)
        .sort();
      const cleanExtensions = labExtensionsVal
        .split(",")
        .map(x => x.trim().toLowerCase())
        .filter(x => x.length > 0)
        .sort();

      const cipherStr = cleanCiphers.join(",");
      const extStr = cleanExtensions.join(",");

      // Mini hashing algorithm simulation (simple custom fn with 12 chars hex)
      const mockHash = (str: string, seed: number) => {
        let h = seed;
        for (let i = 0; i < str.length; i++) {
          h = Math.imul(31, h) + str.charCodeAt(i) | 0;
        }
        const hex = Math.abs(h).toString(16).padStart(8, "0");
        const extra = Math.abs(Math.imul(17, h)).toString(16).padStart(8, "0");
        return (hex + extra).substring(0, 12);
      };

      const ciphersHash = mockHash(cipherStr, 12345);
      const extsHash = mockHash(extStr, 54321);

      const segmentA = `${labProto}${labVer}${labPort}${String(cleanCiphers.length).padStart(2, "0")}${String(cleanExtensions.length).padStart(2, "0")}${labAlpn.padEnd(2, "0").substring(0,2)}`;
      
      setCalculatedLabJa4(`${segmentA}_${ciphersHash}_${extsHash}`);
    } catch (e) {
      // Fail silently
    }
  }, [labProto, labVer, labPort, labCiphersVal, labExtensionsVal, labAlpn]);

  // Analyze the currently active fingerprint using AI (Gemini)
  const handleAIInspection = async (packet: Packet) => {
    setAiLoading(true);
    setAiError(null);
    setAiAnalysis(null);

    try {
      const response = await fetch("/api/gemini/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ja4: packet.ja4,
          type: packet.type,
          host: packet.sni,
          details: packet.details
        })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Failed to analyze TLS fingerprint.");
      }

      setAiAnalysis(data.analysis);
    } catch (error: any) {
      console.error(error);
      setAiError(error?.message || "Internal error requesting artificial intelligence assessment.");
    } finally {
      setAiLoading(false);
    }
  };

  // Dispatch a real alert to user's Telegram Bot
  const triggerManualTestAlert = async () => {
    if (!botToken || !chatId) {
      setAlertError("Please configure your Bot Token and Telegram Chat ID first!");
      return;
    }

    setIsSendingAlert(true);
    setAlertSuccess(null);
    setAlertError(null);

    const testMsg = `🚨 *[JA4 Sentinel IDS Test Log]*\n━━━━━━━━━━━━━━━━━━━━━━\n🎯 *Gateway Verification Attempt*\nStatus: SUCCESS - Sniffer Active\n━━━━━━━━━━━━━━━━━━━━━━\nCalculated TLS signature test template:\n\`t12o080900_3a8c715f2ac1_1a9c3e4f7a2d\`\nSeverity: 🟥 CRITICAL MATCH\nTimestamp: ${new Date().toISOString().replace('T', ' ').substring(0, 19)}`;

    try {
      const resp = await fetch("/api/telegram/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          botToken,
          chatId,
          message: testMsg
        })
      });

      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || "Failed targeting Telegram payload.");
      }

      setAlertSuccess("Instant verification test sent! Check your Telegram companion client.");
      
      const newLog: AlertLog = {
        id: "log_" + Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        botToken: botToken.substring(0, 8) + "...",
        chatId,
        threatName: "Manual Connection Check",
        fingerprint: "t12o080900_3a8c715f2ac1_1a9c3e4f7a2d",
        status: "success",
        message: "Successfully queued packet to Bot API endpoint."
      };
      setAlertLogs(prev => [newLog, ...prev]);
    } catch (e: any) {
      setAlertError(e.message || "Failed verifying credentials.");
      const failedLog: AlertLog = {
        id: "log_" + Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        botToken: botToken.substring(0, 8) + "...",
        chatId,
        threatName: "Manual Diagnostic Failure",
        fingerprint: "",
        status: "failed",
        message: e.message || "Credential rejection."
      };
      setAlertLogs(prev => [failedLog, ...prev]);
    } finally {
      setIsSendingAlert(false);
    }
  };

  // Background automated trigger for actual threats if user is configured
  const dispatchSlackTelegramAlert = async (pkt: Packet) => {
    const alertBody = `🚨 *[JA4 Sentinel Intrusion Alert]*\n━━━━━━━━━━━━━━━━━━━━━━\n🟥 *Threat Detected:* ${pkt.tool}\nSeverity: CRITICAL\n━━━━━━━━━━━━━━━━━━━━━━\n*Source:* \`${pkt.srcIp}:${pkt.srcPort}\`\n*Destination:* \`${pkt.dstIp}:${pkt.dstPort}\`\n*SNI Target:* \`${pkt.sni}\`\n*Calculated JA4 Signature:* \n\`${pkt.ja4}\`\n\n*Action Suggested:* Audit target IP and review telemetry logs using administrative tools.`;

    try {
      await fetch("/api/telegram/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          botToken,
          chatId,
          message: alertBody
        })
      });

      const newLog: AlertLog = {
        id: "log_" + Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        botToken: botToken.substring(0, 8) + "...",
        chatId,
        threatName: pkt.tool,
        fingerprint: pkt.ja4,
        status: "success",
        message: `Automated alert dispatched for threat: ${pkt.tool}`
      };
      setAlertLogs(prev => [newLog, ...prev]);
    } catch (e: any) {
      console.error("Automated background alert error:", e);
    }
  };

  const forceInjectPreset = (preset: { label: string, ja4: string, tool: string, severity: "Safe" | "Warning" | "Critical", ciphers: number, extensions: number, alpn: string }) => {
    const id = "pkt_" + Math.random().toString(36).substr(2, 9);
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    
    const newPacket: Packet = {
      id,
      timestamp,
      srcIp: "192.168.1.185",
      srcPort: Math.floor(Math.random() * 15000) + 50000,
      dstIp: "104.244.42.129",
      dstPort: 443,
      sni: "secure-dns-route.net",
      ja4: preset.ja4,
      type: preset.severity,
      tool: preset.tool,
      details: {
        tlsVersion: preset.ja4.startsWith("t13") ? "1.3" : "1.2",
        protocol: "TCP",
        ciphersCount: preset.ciphers,
        extensionsCount: preset.extensions,
        alpn: preset.alpn,
        ciphersList: ["0xc02b (ECDHE-ECDSA-AES128-GCM-SHA256)", "0xc02f (ECDHE-RSA-AES128-GCM-SHA256)"],
        extensionsList: ["server_name (0x0000)", "supported_groups (0x000a)", "key_share (0x0033)"]
      }
    };

    setPackets(prev => [newPacket, ...prev]);
    setSelectedPacket(newPacket);
    setProcessedCount(prev => prev + 1);

    if (newPacket.type === "Critical" && botToken && chatId) {
      dispatchSlackTelegramAlert(newPacket);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans select-none antialiased p-4 md:p-6">
      {/* Visual background aesthetics */}
      <div className="absolute top-0 left-0 w-full h-[300px] bg-gradient-to-b from-zinc-900/10 to-transparent opacity-40 pointer-events-none" />

      {/* Primary Cyber Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end mb-6 pb-6 border-b border-zinc-900 gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tighter text-emerald-500 uppercase flex items-center gap-2">
            Sentinel IDS <span className="text-zinc-500 text-xs font-mono lowercase">v4.02-ja4</span>
          </h1>
          <p className="text-zinc-500 text-xs mt-1 uppercase tracking-widest font-mono">Real-time TLS Handshake Fingerprinting & Network Monitoring</p>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
          <div className="bg-zinc-900 border border-zinc-800 px-4 py-2 rounded-lg flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${isLiveSniffing ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' : 'bg-zinc-500'} transition-all duration-300`} />
            <span className="text-xs font-mono text-zinc-300">SYSTEM: {isLiveSniffing ? 'ACTIVE' : 'HALTED'}</span>
            <button 
              onClick={() => setIsLiveSniffing(!isLiveSniffing)}
              className="ml-2 hover:bg-zinc-800 p-1 rounded text-zinc-400 hover:text-emerald-400 transition"
              title={isLiveSniffing ? "Pause client-side simulation" : "Resume simulated stream"}
            >
              <RefreshCw className="w-3 h-3" />
            </button>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 px-4 py-2 rounded-lg flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${botToken && chatId ? 'bg-blue-500 shadow-[0_0_8px_#3b82f6]' : 'bg-zinc-500'} transition-all duration-300`} />
            <span className="text-xs font-mono text-zinc-300">TELEBOT: {botToken && chatId ? 'CONNECTED' : 'NOT CONFIGURED'}</span>
          </div>
        </div>
      </div>

      {/* Main Bento Grid Layout */}
      <div className="flex-1 max-w-[1600px] w-full mx-auto lg:grid lg:grid-cols-5 gap-4 gap-y-4">
        
        {/* Navigation / Control Panel Layout */}
        <div className="lg:col-span-1 flex flex-col space-y-3 mb-6 lg:mb-0">
          <p className="text-zinc-500 uppercase text-[10px] font-mono tracking-wider font-semibold px-2">Operator Workspace</p>

          <button
            onClick={() => setActiveMenu("console")}
            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition duration-150 border text-left text-sm ${
              activeMenu === "console"
                ? "bg-zinc-900 border-zinc-700 text-emerald-400 shadow-lg"
                : "bg-zinc-900/30 hover:bg-zinc-900/80 border-zinc-800/80 text-zinc-400 hover:text-zinc-100"
            }`}
          >
            <Activity className="w-4 h-4 shrink-0" />
            <div className="flex-1">
              <span className="font-semibold block text-xs">Live Stream Console</span>
              <span className="text-[10px] text-zinc-500 font-mono">Stream & analyze packers</span>
            </div>
            <ChevronRight className="w-3.5 h-3.5 text-zinc-600" />
          </button>

          <button
            onClick={() => setActiveMenu("config")}
            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition duration-150 border text-left text-sm ${
              activeMenu === "config"
                ? "bg-zinc-900 border-zinc-700 text-emerald-400 shadow-lg"
                : "bg-zinc-900/30 hover:bg-zinc-900/80 border-zinc-800/80 text-zinc-400 hover:text-zinc-100"
            }`}
          >
            <Settings className="w-4 h-4 shrink-0" />
            <div className="flex-1">
              <span className="font-semibold block text-xs">Telegram Alert Hub</span>
              <span className="text-[10px] text-zinc-500 font-mono">Bot endpoints integration</span>
            </div>
            <ChevronRight className="w-3.5 h-3.5 text-zinc-600" />
          </button>

          <button
            onClick={() => setActiveMenu("exporter")}
            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition duration-150 border text-left text-sm ${
              activeMenu === "exporter"
                ? "bg-zinc-900 border-zinc-700 text-emerald-400 shadow-lg"
                : "bg-zinc-900/30 hover:bg-zinc-900/80 border-zinc-800/80 text-zinc-400 hover:text-zinc-100"
            }`}
          >
            <FileCode className="w-4 h-4 shrink-0" />
            <div className="flex-1">
              <span className="font-semibold block text-xs">Python IDS Exporter</span>
              <span className="text-[10px] text-zinc-500 font-mono">Download source script</span>
            </div>
            <ChevronRight className="w-3.5 h-3.5 text-zinc-600" />
          </button>

          <button
            onClick={() => setActiveMenu("lab")}
            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition duration-150 border text-left text-sm ${
              activeMenu === "lab"
                ? "bg-zinc-900 border-zinc-700 text-emerald-400 shadow-lg"
                : "bg-zinc-900/30 hover:bg-zinc-900/80 border-zinc-800/80 text-zinc-400 hover:text-zinc-100"
            }`}
          >
            <Cpu className="w-4 h-4 shrink-0" />
            <div className="flex-1">
              <span className="font-semibold block text-xs">Interactive JA4 Lab</span>
              <span className="text-[10px] text-zinc-500 font-mono">Decode client TLS handshakes</span>
            </div>
            <ChevronRight className="w-3.5 h-3.5 text-zinc-600" />
          </button>

          <div className="border border-zinc-800 bg-zinc-900/30 p-4 rounded-xl text-xs space-y-3.5">
            <p className="font-mono text-[10px] text-zinc-500 uppercase font-semibold">Threat Intel Catalog</p>
            <div className="space-y-2.5">
              {REFERENCE_THREATS.map(threat => (
                <div key={threat.ja4} className="border border-rose-950/40 bg-rose-950/10 p-2 rounded-lg">
                  <p className="font-semibold text-zinc-200 text-[11px] truncate">{threat.name}</p>
                  <p className="font-mono text-[9px] text-rose-400 select-all truncate mt-0.5">{threat.ja4}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Content Console Panel */}
        <div className="lg:col-span-4 flex flex-col min-h-[600px] gap-4">
          
          {/* Menu Window - CONSOLE */}
          {activeMenu === "console" && (
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
              
              {/* Traffic Logger Panel */}
              <div className="xl:col-span-8 bg-zinc-900/50 border border-zinc-800 rounded-2xl p-5 relative overflow-hidden flex flex-col hover:border-zinc-700/50 transition-all duration-300">
                
                <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                  <div className="flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-emerald-500" />
                    <h2 className="font-sans font-semibold text-zinc-100 text-xs uppercase tracking-wider">Ingress Traffic Feed</h2>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-mono text-zinc-400 bg-zinc-950/60 border border-zinc-800/80 px-2 py-1 rounded">Quick Simulate:</span>
                    <div className="flex space-x-1">
                      <button 
                        onClick={() => forceInjectPreset({
                          label: "CS",
                          ja4: "t12o080900_3a8c715f2ac1_1a9c3e4f7a2d",
                          tool: "Cobalt Strike Beacon Target Injection",
                          severity: "Critical",
                          ciphers: 8,
                          extensions: 9,
                          alpn: "None"
                        })}
                        className="text-[9px] font-mono border border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20 px-1.5 py-1 rounded text-rose-400 transition"
                        title="Simulate Cobalt Strike Connection"
                      >
                        CS Beacon
                      </button>
                      <button 
                        onClick={() => forceInjectPreset({
                          label: "Tor",
                          ja4: "t13d1915h2_9e2a5f4c3d2b_3a5c2e1f9b8d",
                          tool: "Tor TLS Relay Node Route Check",
                          severity: "Warning",
                          ciphers: 19,
                          extensions: 15,
                          alpn: "http/1.1"
                        })}
                        className="text-[9px] font-mono border border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20 px-1.5 py-1 rounded text-amber-400 transition"
                        title="Simulate Tor Browser Connection"
                      >
                        Tor Browser
                      </button>
                    </div>
                  </div>
                </div>

                {/* Packet Record Table */}
                <div className="overflow-x-auto min-h-[460px]">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-zinc-800 text-zinc-500 font-mono text-[10px] uppercase">
                        <th className="pb-2.5 font-semibold">Timestamp</th>
                        <th className="pb-2.5 font-semibold">Source ➝ Destination</th>
                        <th className="pb-2.5 font-semibold">Match Application</th>
                        <th className="pb-2.5 font-semibold">JA4 Fingerprint</th>
                        <th className="pb-2.5 font-semibold text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60">
                      {packets.map(pkt => {
                        const statusColors = {
                          Safe: "text-emerald-500 bg-emerald-500/10 border-emerald-500/20",
                          Warning: "text-amber-500 bg-amber-500/10 border-amber-500/20",
                          Critical: "text-rose-500 bg-rose-500/10 border-rose-500/20"
                        };

                        return (
                          <tr
                            key={pkt.id}
                            onClick={() => setSelectedPacket(pkt)}
                            className={`group cursor-pointer border-b border-zinc-900/40 transition-all ${
                              selectedPacket.id === pkt.id 
                                ? 'bg-zinc-850/60 text-emerald-400' 
                                : 'hover:bg-zinc-900/40 text-zinc-300'
                            }`}
                          >
                            <td className="py-3 font-mono text-[10px] text-zinc-500 truncate">{pkt.timestamp.split(" ")[1]}</td>
                            <td className="py-3 font-mono text-[11px]">
                              <span className="text-zinc-400 font-semibold">{pkt.srcIp}</span>
                              <span className="text-zinc-600 mx-1">➝</span>
                              <span className="text-zinc-300 font-semibold">{pkt.dstIp}</span>
                              <p className="text-[9px] text-zinc-500 mt-0.5">SNI: <span className="text-zinc-400">{pkt.sni}</span></p>
                            </td>
                            <td className="py-3 text-zinc-200">
                              <span className="block truncate max-w-[120px] font-semibold">{pkt.tool}</span>
                              <span className="text-[9px] font-mono text-zinc-500">Port {pkt.dstPort}</span>
                            </td>
                            <td className="py-3 font-mono text-[10px] text-emerald-400 select-all truncate max-w-[160px]" title={pkt.ja4}>
                              {pkt.ja4}
                            </td>
                            <td className="py-3 text-right">
                              <span className={`inline-block text-[9px] font-semibold font-mono px-2.5 py-1 rounded border ${statusColors[pkt.type]}`}>
                                {pkt.type.toUpperCase()}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {packets.length === 0 && (
                    <div className="text-center py-12 text-zinc-600">
                      <Terminal className="w-8 h-8 mx-auto stroke-1" />
                      <p className="mt-2 font-mono">No network captures in this pipeline session.</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Deep Packet Inspector Panel (Split Screen, Right Column) */}
              <div className="xl:col-span-4 flex flex-col space-y-4">
                
                {/* Visual Decoder Board */}
                <div className="bg-zinc-900/50 border border-zinc-800 rounded-2xl p-5 relative overflow-hidden hover:border-zinc-700/50 transition-all duration-300">
                  <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
                    <Cpu className="w-24 h-24 text-white" />
                  </div>
                  <h3 className="font-sans font-semibold text-zinc-100 text-xs uppercase tracking-wider mb-4 flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-emerald-500" />
                    <span>TLS Handshake Fingerprint Metadata</span>
                  </h3>

                  {/* Packet Overview details */}
                  <div className="bg-zinc-950/40 border border-zinc-800 rounded-xl p-3 mb-4 text-xs font-mono grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-zinc-500 text-[10px] block font-mono">Target Host (SNI)</span>
                      <span className="text-emerald-400 font-bold truncate block">{selectedPacket.sni}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500 text-[10px] block font-mono">Host Communication Endpoint</span>
                      <span className="text-zinc-300 truncate block">{selectedPacket.srcIp}:{selectedPacket.srcPort}</span>
                    </div>
                  </div>

                  {/* Fingerprint Segment breakdowns */}
                  <div className="space-y-3 px-1">
                    
                    {/* Segment A Container */}
                    <div className="bg-zinc-950/60 p-3.5 rounded-xl border border-zinc-800">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-[10px] font-bold font-sans text-emerald-400">JA4 SEGMENT A (Metadata)</span>
                        <span className="font-mono text-xs bg-zinc-900 text-emerald-400 border border-zinc-800 px-2 py-0.5 rounded font-semibold">
                          {selectedPacket.ja4.split("_")[0]}
                        </span>
                      </div>
                      <p className="text-[10px] text-zinc-400 leading-relaxed mb-3">
                        Parsed handshake metadata: transport protocols, extensions list size, destination port features, and negotiated protocols.
                      </p>
                      
                      {/* Dynamic segments parameters */}
                      <div className="grid grid-cols-3 gap-1.5 font-mono text-[9px] text-center text-zinc-350">
                        <div className="bg-zinc-900/60 border border-zinc-800 p-1.5 rounded">
                          <span className="text-zinc-500 block">PROTOCOL</span>
                          <span className="font-bold text-zinc-200 uppercase">{selectedPacket.details.protocol}</span>
                        </div>
                        <div className="bg-zinc-900/60 border border-zinc-800 p-1.5 rounded">
                          <span className="text-zinc-500 block">TLS VERSION</span>
                          <span className="font-bold text-zinc-200">TLS {selectedPacket.details.tlsVersion}</span>
                        </div>
                        <div className="bg-zinc-900/60 border border-zinc-800 p-1.5 rounded">
                          <span className="text-zinc-500 block">ALPN IND</span>
                          <span className="font-bold text-zinc-200">{selectedPacket.details.alpn !== "None" ? selectedPacket.details.alpn : "N/A"}</span>
                        </div>
                        <div className="bg-zinc-900/60 border border-zinc-800 p-1.5 rounded col-span-1.5">
                          <span className="text-zinc-500 block font-mono">CIPHER COUNT</span>
                          <span className="font-bold text-zinc-200">{selectedPacket.details.ciphersCount} in list</span>
                        </div>
                        <div className="bg-zinc-900/60 border border-zinc-800 p-1.5 rounded col-span-1.5">
                          <span className="text-zinc-500 block font-mono">EXTENSION COUNT</span>
                          <span className="font-bold text-zinc-200">{selectedPacket.details.extensionsCount} in list</span>
                        </div>
                      </div>
                    </div>

                    {/* Segment B Container */}
                    <div className="bg-zinc-950/60 p-3.5 rounded-xl border border-zinc-800 font-mono">
                      <div className="flex justify-between items-center mb-1.5">
                        <span className="text-[10px] font-bold text-emerald-400">JA4 SEGMENT B (Ciphers Hash)</span>
                        <span className="font-mono text-xs bg-zinc-900 text-emerald-400 border border-zinc-800 px-2 py-0.5 rounded font-semibold">
                          {selectedPacket.ja4.split("_")[1]}
                        </span>
                      </div>
                      <p className="text-[10px] text-zinc-400 leading-relaxed mb-2.5">
                        SHA-256 truncation (12 hex digits) of sorted active client cipher suites.
                      </p>
                      <div className="bg-zinc-900/60 border border-zinc-800 p-2 rounded-lg">
                        <span className="text-zinc-500 text-[9px] font-mono uppercase block mb-1">Ciphers in footprint (First 3):</span>
                        <ul className="text-[9px] font-mono text-zinc-300 space-y-0.5 list-inside list-disc">
                          {selectedPacket.details.ciphersList?.map((cipher, idx) => (
                            <li key={idx} className="truncate">{cipher}</li>
                          )) || <li className="italic text-zinc-500">List not populated.</li>}
                        </ul>
                      </div>
                    </div>

                    {/* Segment C Container */}
                    <div className="bg-zinc-950/60 p-3.5 rounded-xl border border-zinc-800 font-mono">
                      <div className="flex justify-between items-center mb-1.5">
                        <span className="text-[10px] font-bold text-emerald-400">JA4 SEGMENT C (Extensions Hash)</span>
                        <span className="font-mono text-xs bg-zinc-900 text-emerald-400 border border-zinc-800 px-2 py-0.5 rounded font-semibold">
                          {selectedPacket.ja4.split("_")[2]}
                        </span>
                      </div>
                      <p className="text-[10px] text-zinc-400 leading-relaxed mb-2.5">
                        SHA-256 truncation (12 hex digits) of sorted extensions and signatures.
                      </p>
                      <div className="bg-zinc-900/60 border border-zinc-800 p-2 rounded-lg">
                        <span className="text-zinc-500 text-[9px] font-mono uppercase block mb-1">Parsed Extensions (First 3):</span>
                        <ul className="text-[9px] font-mono text-zinc-300 space-y-0.5 list-inside list-disc">
                          {selectedPacket.details.extensionsList?.map((ext, idx) => (
                            <li key={idx} className="truncate">{ext}</li>
                          )) || <li className="italic text-zinc-500">List not populated.</li>}
                        </ul>
                      </div>
                    </div>

                  </div>
                </div>

                {/* AI / Threat Hunter Assessment */}
                <div className="bg-zinc-900/50 border border-zinc-800 rounded-2xl p-5 relative overflow-hidden flex-1 hover:border-zinc-700/50 transition-all duration-300">
                  <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                    <div className="flex items-center space-x-2">
                      <Sparkles className="w-4 h-4 text-emerald-500 animate-pulse" />
                      <h3 className="font-sans font-semibold text-zinc-100 text-xs uppercase tracking-wider">AI Security Advisor</h3>
                    </div>

                    <button
                      onClick={() => handleAIInspection(selectedPacket)}
                      disabled={aiLoading}
                      className="text-[10px] font-mono bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 text-emerald-400 border border-zinc-700 px-3 py-1.5 rounded-lg font-semibold tracking-wide transition flex items-center space-x-1.5"
                    >
                      {aiLoading ? (
                        <>
                          <RefreshCw className="w-3 h-3 animate-spin" />
                          <span>Advising Engine...</span>
                        </>
                      ) : (
                        <>
                          <Cpu className="w-3 h-3" />
                          <span>Assess Fingerprint</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Assessment Display Area */}
                  <div className="bg-zinc-950/60 border border-zinc-800 rounded-xl p-4 font-mono text-[10.5px] leading-relaxed min-h-[160px] text-zinc-300 overflow-y-auto max-h-[300px]">
                    {aiLoading && (
                      <div className="space-y-3.5 py-4">
                        <p className="text-emerald-500 animate-pulse">*** CONNECTING CLOUD RUN GEN INTEL NETWORK ***</p>
                        <p className="text-zinc-500 animate-pulse text-[10px]">Processing JA4: {selectedPacket.ja4}</p>
                        <p className="text-zinc-500 animate-pulse text-[10px]">Comparing signatures against active threat databases...</p>
                        <div className="h-1 w-full bg-zinc-900 rounded overflow-hidden">
                          <div className="h-full bg-emerald-500 animate-infinite-loading w-[35%] rounded" />
                        </div>
                      </div>
                    )}

                    {!aiLoading && !aiAnalysis && !aiError && (
                      <div className="text-zinc-500 text-center py-6">
                        <Info className="w-7 h-7 mx-auto stroke-1 mb-2 text-zinc-650" />
                        <p>Select a packet item from the console ticker, then trigger instant AI assessment to consult the security advisor analysis reports.</p>
                      </div>
                    )}

                    {!aiLoading && aiError && (
                      <div className="text-rose-400 border border-rose-950 bg-rose-950/20 p-3.5 rounded-xl">
                        <AlertTriangle className="w-4 h-4 mb-2 text-rose-500" />
                        <span className="font-semibold block text-xs font-sans text-rose-300">Analysis Gateway Rejection:</span>
                        <p className="mt-1 leading-relaxed">{aiError}</p>
                        <p className="text-[9px] text-zinc-500 mt-2">Verify that your GEMINI_API_KEY environment variable is declared inside the Settings panel.</p>
                      </div>
                    )}

                    {!aiLoading && aiAnalysis && (
                      <div className="whitespace-pre-wrap max-w-full text-zinc-200">
                        {aiAnalysis}
                      </div>
                    )}
                  </div>
                </div>

              </div>

            </div>
          )}

          {/* Menu Window - TELEGRAM CONFIG */}
          {activeMenu === "config" && (
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-2xl p-6 relative overflow-hidden">
              
              <div className="mb-6">
                <h2 className="font-sans font-semibold text-sm uppercase tracking-wider text-zinc-100 flex items-center space-x-2">
                  <Settings className="w-5 h-5 text-emerald-500" />
                  <span>Telegram Alerting Configuration</span>
                </h2>
                <p className="text-zinc-400 text-xs mt-1.5">
                  Tie your network sniffer alerts to a real Telegram Bot channel. When a simulated or live critical threat matches, the dashboard and python script automatically propagate the packet details.
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Form Setup Fields */}
                <div className="lg:col-span-7 space-y-5">
                  <div className="bg-zinc-950/40 border border-zinc-800 p-5 rounded-xl space-y-4">
                    <div>
                      <label className="block text-zinc-300 text-[10px] font-mono mb-2 font-semibold uppercase tracking-wider">Telegram Bot Token</label>
                      <input
                        type="text"
                        placeholder="e.g. 7123951239:AAGh9_X1zE9ab1..."
                        value={botToken}
                        onChange={(e) => setBotToken(e.target.value)}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-zinc-700 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20"
                      />
                    </div>

                    <div>
                      <label className="block text-zinc-300 text-[10px] font-mono mb-2 font-semibold uppercase tracking-wider">Telegram Chat ID</label>
                      <input
                        type="text"
                        placeholder="e.g. 195204215"
                        value={chatId}
                        onChange={(e) => setChatId(e.target.value)}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-zinc-700 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20"
                      />
                    </div>

                    <div className="pt-2">
                      <button
                        onClick={triggerManualTestAlert}
                        disabled={isSendingAlert || !botToken || !chatId}
                        className="w-full bg-emerald-600 hover:bg-emerald-450 disabled:opacity-50 text-white py-2.5 rounded-lg text-xs font-semibold tracking-wide transition shadow-lg flex items-center justify-center space-x-2"
                      >
                        {isSendingAlert ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Dispatching Telegram Payload...</span>
                          </>
                        ) : (
                          <>
                            <Send className="w-4 h-4 text-emerald-250 animate-pulse" />
                            <span>Validate Connection & Send Test Alert</span>
                          </>
                        )}
                      </button>
                    </div>

                    {/* Form Notifications feedback */}
                    {alertSuccess && (
                      <div className="bg-emerald-950/30 border border-emerald-900 p-3 rounded-lg text-xs flex items-start space-x-2.5 text-emerald-300 animate-fadeIn font-mono">
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        <p>{alertSuccess}</p>
                      </div>
                    )}

                    {alertError && (
                      <div className="bg-rose-950/30 border border-rose-900 p-3 rounded-lg text-xs flex items-start space-x-2.5 text-rose-300 animate-fadeIn font-mono">
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                        <p>{alertError}</p>
                      </div>
                    )}
                  </div>

                  {/* Step By Step Instructions */}
                  <div className="bg-zinc-950/40 border border-zinc-805 p-5 rounded-xl text-xs text-zinc-400">
                    <h3 className="text-zinc-200 font-sans font-semibold mb-3 flex items-center space-x-1.5 uppercase tracking-wider text-[11px]">
                      <HelpCircle className="w-4 h-4 text-emerald-500" />
                      <span>Setup Walkthrough for Your Telegram Bot</span>
                    </h3>
                    <ol className="list-decimal list-inside space-y-2 leading-relaxed font-sans text-xs">
                      <li>
                        Launch Telegram, search for <span className="font-semibold text-white">@BotFather</span> and initiate a query (/start).
                      </li>
                      <li>
                        Exert commands: Send <span className="font-mono text-emerald-400">/newbot</span> and choose names. Copy the long <span className="font-semibold text-white">HTTP API Token</span>.
                      </li>
                      <li>
                        To fetch your chat ID, search for <span className="font-semibold text-white">@userinfobot</span> inside Telegram and send any message. It will reply with your target numeric <span className="font-semibold text-white">Id</span>.
                      </li>
                      <li>
                        Enter both values here to run instant tests.
                      </li>
                    </ol>
                  </div>
                </div>

                {/* Dispatch Logs */}
                <div className="lg:col-span-5 flex flex-col h-full">
                  <div className="bg-zinc-950/60 border border-zinc-800 rounded-xl p-4 flex-1 flex flex-col min-h-[300px]">
                    <span className="text-[10px] font-mono text-zinc-500 uppercase font-semibold block mb-3.5">Recent Alert Fire Logs</span>
                    
                    <div className="space-y-3 overflow-y-auto max-h-[340px] flex-1">
                      {alertLogs.map(log => (
                        <div key={log.id} className="border border-zinc-800/80 bg-zinc-900/40 p-3 rounded-lg text-[11px] font-mono">
                          <div className="flex justify-between font-bold mb-1">
                            <span className="text-zinc-300">{log.threatName}</span>
                            <span className={`text-[10px] ${log.status === "success" ? 'text-emerald-400' : 'text-rose-400'}`}>
                              {log.status.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-zinc-400 space-y-0.5">
                            <p>Target Bot: <span className="text-zinc-500">{log.botToken}</span></p>
                            <p>Chat ID: <span className="text-zinc-500">{log.chatId}</span></p>
                            <p className="text-zinc-500 text-[10px] mt-1">{log.message}</p>
                          </div>
                          <span className="block text-right text-[9px] text-zinc-650 mt-1">{log.timestamp}</span>
                        </div>
                      ))}
                      {alertLogs.length === 0 && (
                        <div className="text-center py-12 text-zinc-600 font-mono text-xs">
                          <span>[ALERT QUEUE EMPTY]</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* Menu Window - EXPORTER */}
          {activeMenu === "exporter" && (
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-2xl p-6 relative overflow-hidden">
              
              <div className="mb-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <h2 className="font-sans font-semibold text-sm uppercase tracking-wider text-zinc-100 flex items-center space-x-2">
                    <FileCode className="w-5 h-5 text-emerald-500" />
                    <span>Python Network Sniffer Engine</span>
                  </h2>
                  <p className="text-zinc-400 text-xs mt-1.5">
                    Execute raw traffic sniffing on your local servers or test VMs to analyze native socket events!
                  </p>
                </div>

                <a
                  href={`/api/download/script?botToken=${encodeURIComponent(botToken)}&chatId=${encodeURIComponent(chatId)}`}
                  className="bg-emerald-600 hover:bg-emerald-450 text-white px-4 py-2.5 rounded-xl font-semibold text-xs tracking-wide transition shadow-lg flex items-center justify-center space-x-2"
                >
                  <Download className="w-4 h-4 text-emerald-250 animate-pulse" />
                  <span>Download Auto-configured Python IDS Script</span>
                </a>
              </div>

              {/* Dynamic source code overview */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Requirements / Installation notes */}
                <div className="lg:col-span-5 space-y-4">
                  <div className="bg-zinc-950/60 p-5 rounded-xl border border-zinc-800 text-xs">
                    <h3 className="font-sans font-semibold text-zinc-200 mb-3.5 flex items-center space-x-1.5 uppercase tracking-wider text-[11px]">
                      <Terminal className="w-4 h-4 text-emerald-500" />
                      <span>Host Server Setup Guidelines</span>
                    </h3>
                    
                    <div className="space-y-4 font-sans text-xs">
                      <div>
                        <span className="text-zinc-500 block text-[10px] uppercase font-mono mb-1 font-semibold">1. Setup Python Dependencies:</span>
                        <div className="bg-zinc-900 border border-zinc-800 p-2.5 rounded-lg font-mono text-emerald-400 select-all relative group">
                          pip install scapy pyTelegramBotAPI
                        </div>
                      </div>

                      <div>
                        <span className="text-zinc-500 block text-[10px] uppercase font-mono mb-1 font-semibold">2. Running constraints (Needs sudo privileges):</span>
                        <p className="text-zinc-400 leading-relaxed font-sans mt-1">
                          Raw socket sniffing requires access to diagnostic hardware frames, demanding root access on Linux/macOS clusters.
                        </p>
                        <div className="bg-zinc-900 border border-zinc-800 p-2.5 rounded-lg font-mono text-rose-400 mt-2 select-all font-bold">
                          sudo python3 ja4_ids.py
                        </div>
                      </div>

                      <div className="border border-zinc-800 bg-zinc-930/40 p-3.5 rounded-xl font-sans">
                        <span className="text-zinc-300 font-semibold block mb-1">Fingerprint Capabilities Inside Script:</span>
                        <p className="text-[11px] text-zinc-400 leading-relaxed">
                          The python script features full packet structure parsing. It automatically listens for TLS client hellos, strips random GREASE bytes, sorts TLS signatures alphabetically, and calculates the SHA-256 segment hashes to issue alert signals safely.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Source code viewer */}
                <div className="lg:col-span-7 flex flex-col h-full">
                  <div className="bg-zinc-950/60 border border-zinc-800 rounded-xl p-4 flex-1 flex flex-col">
                    <span className="text-[10px] font-mono text-zinc-500 uppercase font-semibold block mb-2.5">Autoconfigured Source Preview</span>
                    <div className="bg-zinc-950/80 border border-zinc-800 rounded-lg p-3.5 font-mono text-[10.5px] text-zinc-350 leading-relaxed overflow-x-auto max-h-[440px] flex-1">
                      <p className="text-emerald-500 font-semibold"># Configure Bot credentials injected dynamically:</p>
                      <p className="text-white">TELEGRAM_BOT_TOKEN = <span className="text-emerald-400">"{botToken || 'YOUR_TELEGRAM_BOT_TOKEN'}"</span></p>
                      <p className="text-white">TELEGRAM_CHAT_ID = <span className="text-emerald-400">"{chatId || 'YOUR_TELEGRAM_CHAT_ID'}"</span></p>
                      
                      <p className="text-zinc-500 mt-3">...</p>
                      <p className="text-emerald-400 font-semibold">def parse_tls_client_hello(raw_payload):</p>
                      <p className="text-zinc-400 pl-4"># Parses basic Client Handshake metadata...</p>
                      <p className="text-zinc-400 pl-4"># Filters GREASE values: c & 0x0f0f != 0x0a0a</p>
                      
                      <p className="text-zinc-500 mt-2">...</p>
                      <p className="text-emerald-400 font-semibold">def compute_ja4(tls_data, dest_port=443):</p>
                      <p className="text-zinc-400 pl-4"># Computes JA4_A segment...</p>
                      <p className="text-zinc-400 pl-4"># Computes Segment B (sorted ciphers hashed & truncated)...</p>
                      <p className="text-zinc-400 pl-4"># Computes Segment C (sorted extensions hashed & truncated)...</p>
                      
                      <p className="text-zinc-500 mt-2">...</p>
                      <p className="text-emerald-400 font-semibold">def trigger_intrusion_alert(src_ip, sport, dst_ip, dport, fingerprint, threat):</p>
                      <p className="text-zinc-400 pl-4"># Transmit payload details instantly over API channels...</p>
                      <p className="text-emerald-400 pl-4 font-semibold">bot.send_message(TELEGRAM_CHAT_ID, alert_body, parse_mode='Markdown')</p>
                    </div>
                  </div>
                </div>

              </div>
            </div>
          )}

          {activeMenu === "lab" && (
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-2xl p-6 relative overflow-hidden animate-fadeIn">
              
              <div className="mb-6">
                <h2 className="font-sans font-semibold text-sm uppercase tracking-wider text-zinc-100 flex items-center space-x-2">
                  <Cpu className="w-5 h-5 text-emerald-500" />
                  <span>Interactive JA4 Signature Sandbox</span>
                </h2>
                <p className="text-zinc-400 text-xs mt-1.5">
                  Playground module: Experiment with custom ciphers, ALPN indicators, and protocols to compute host fingerprint signatures in real-time.
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                
                {/* Lab parameters settings */}
                <div className="lg:col-span-7 bg-zinc-950/40 border border-zinc-805 p-5 rounded-xl space-y-4">
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <label className="block text-zinc-450 text-[10px] font-mono mb-2 uppercase font-semibold">Transport Protocol</label>
                      <select
                        value={labProto}
                        onChange={(e) => setLabProto(e.target.value)}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-2 py-1.5 text-xs text-white uppercase focus:outline-none focus:border-emerald-500"
                      >
                        <option value="t">t (TCP)</option>
                        <option value="q">q (QUIC)</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-zinc-455 text-[10px] font-mono mb-2 uppercase font-semibold">TLS Version</label>
                      <select
                        value={labVer}
                        onChange={(e) => setLabVer(e.target.value)}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500"
                      >
                        <option value="13">1.3 (modern)</option>
                        <option value="12">1.2</option>
                        <option value="11">1.1</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-zinc-455 text-[10px] font-mono mb-2 uppercase font-semibold">Destination Port</label>
                      <select
                        value={labPort}
                        onChange={(e) => setLabPort(e.target.value)}
                        className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500"
                      >
                        <option value="d">Default (443)</option>
                        <option value="o">Other Port</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-zinc-300 text-[10px] font-mono mb-1.5 uppercase font-semibold">ALPN Protocol Token (e.g. h2, http/1.1)</label>
                    <input
                      type="text"
                      placeholder="e.g. h2"
                      value={labAlpn}
                      onChange={(e) => setLabAlpn(e.target.value)}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-zinc-700 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20"
                    />
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <label className="block text-zinc-300 text-[10px] font-mono uppercase font-semibold">Cipher Suites hex entries (split by commas)</label>
                      <span className="text-[10px] text-zinc-550 font-mono">excluding GREASE</span>
                    </div>
                    <textarea
                      rows={2}
                      value={labCiphersVal}
                      onChange={(e) => setLabCiphersVal(e.target.value)}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-zinc-700 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20"
                      placeholder="e.g. 0x1301, 0x1302, 0xc02b"
                    />
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <label className="block text-zinc-300 text-[10px] font-mono uppercase font-semibold">Extensions hex order values (split by commas)</label>
                      <span className="text-[10px] text-zinc-550 font-mono">excluding GREASE</span>
                    </div>
                    <textarea
                      rows={2}
                      value={labExtensionsVal}
                      onChange={(e) => setLabExtensionsVal(e.target.value)}
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-zinc-700 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/20"
                      placeholder="e.g. 0x0000, 0x000a, 0x002b"
                    />
                  </div>
                </div>

                {/* Simulated Signature Outputs */}
                <div className="lg:col-span-12 xl:col-span-5 bg-zinc-950/60 border border-zinc-800 rounded-xl p-5 space-y-4">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase font-semibold block">Calculated Resulting Fingerprint</span>
                  
                  <div className="bg-zinc-950 p-4 border border-zinc-850 rounded-xl text-center">
                    <span className="text-[10px] font-mono text-zinc-500 block mb-1">Dynamic Signature Value:</span>
                    <span className="font-mono text-xs select-all bg-emerald-950/20 text-emerald-400 border border-emerald-500/30 px-2.5 py-2 rounded-lg font-bold block overflow-x-auto whitespace-nowrap">
                      {calculatedLabJa4}
                    </span>
                  </div>

                  <div className="border border-zinc-800 bg-zinc-900/40 p-3.5 rounded-lg text-xs leading-relaxed text-zinc-400">
                    <span className="text-zinc-200 font-bold block mb-1 font-sans text-xs uppercase tracking-wider">How JA4 segments calculated underneath:</span>
                    <ul className="list-disc list-inside space-y-1.5 mt-2 font-mono text-[11px]">
                      <li><span className="text-emerald-500 font-bold">Segment A ({calculatedLabJa4.split("_")[0] || ""}):</span> Length 10. Formats protocols, counts sizes.</li>
                      <li><span className="text-emerald-500 font-bold">Segment B ({calculatedLabJa4.split("_")[1] || ""}):</span> Hashed sorted list of custom ciphers.</li>
                      <li><span className="text-emerald-500 font-bold">Segment C ({calculatedLabJa4.split("_")[2] || ""}):</span> Hashed sorted list of custom extension keys.</li>
                    </ul>
                  </div>
                </div>

              </div>
            </div>
          )}

        </div>

      </div>

      {/* Cyber SOC Footer */}
      <footer className="border-t border-zinc-850 bg-zinc-950 py-5 px-6 mt-12 flex flex-col sm:flex-row items-center justify-between text-[11px] text-zinc-500 font-mono tracking-wider">
        <div className="flex items-center space-x-2">
          <Shield className="w-3.5 h-3.5 text-zinc-700" />
          <span className="font-semibold text-zinc-400">JA4 SENTINEL SYSTEMS CORE</span>
        </div>
        <div className="mt-2 sm:mt-0 space-x-4">
          <span>PIPELINE BUFFER OK</span>
          <span>© 2026 WORKSPACE</span>
        </div>
      </footer>
    </div>
  );
}
