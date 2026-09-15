"""Automated Tests for Wave 1: Deep Network Protocol Dissectors & DPI."""

import base64
import binascii
import struct
import pytest
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.protocols.schemas import ProtocolType, DissectionRequest, BatchDissectionRequest
from cybershield.protocols.dissector_engine import ProtocolDissectorEngine
from cybershield.protocols.dns_decoder import DNSDecoder
from cybershield.protocols.http2_decoder import HTTPDecoder
from cybershield.protocols.tls_decoder import TLSDecoder, KNOWN_MALICIOUS_JA3
from cybershield.protocols.smb_decoder import SMBDecoder
from cybershield.protocols.kerberos_decoder import KerberosDecoder
from cybershield.protocols.rdp_decoder import RDPDecoder
from cybershield.protocols.modbus_decoder import ModbusDecoder
from cybershield.protocols.dnp3_decoder import DNP3Decoder
from cybershield.protocols.bacnet_decoder import BACnetDecoder
from cybershield.protocols.mqtt_decoder import MQTTDecoder


def test_dns_dissection_and_tunneling_detection():
    """Verify DNS header parsing, A record extraction, and tunneling heuristics."""
    # 1. Standard DNS Query for 'example.com'
    # ID=0x1234, Flags=0x0100 (Standard Query, RD=1), QDCOUNT=1, AN=0, NS=0, AR=0
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q_name = b"\x07example\x03com\x00"
    q_type_cls = struct.pack("!HH", 1, 1)  # A, IN
    dns_pkt = hdr + q_name + q_type_cls

    res = DNSDecoder.decode(dns_pkt)
    assert res.protocol == ProtocolType.DNS
    assert res.headers["transaction_id"] == "0x1234"
    assert res.headers["is_response"] is False
    assert len(res.payload_fields["questions"]) == 1
    assert res.payload_fields["questions"][0]["name"] == "example.com"
    assert res.payload_fields["questions"][0]["type"] == "A"
    assert res.is_suspicious is False

    # 2. DNS Tunneling Query with high-entropy Base64 subdomain
    tunnel_sub = b"a8f93bc091de45fa8871239abcef10928374650192837465"
    tunnel_name = bytes([len(tunnel_sub)]) + tunnel_sub + b"\x06tunnel\x03com\x00"
    tunnel_pkt = hdr + tunnel_name + q_type_cls

    res_tunnel = DNSDecoder.decode(tunnel_pkt)
    assert res_tunnel.is_suspicious is True
    rule_ids = [a.rule_id for a in res_tunnel.anomalies]
    assert "DNS-TUNNEL-001" in rule_ids


def test_http1_and_http2_dissection():
    """Verify HTTP/1.x smuggling/SQLi and HTTP/2 Rapid Reset detection."""
    # 1. Malicious HTTP/1.1 with Request Smuggling (CL+TE) and SQLi
    smuggle_http = (
        "POST /login.php HTTP/1.1\r\n"
        "Host: target.internal\r\n"
        "User-Agent: sqlmap/1.7#dev\r\n"
        "Content-Length: 44\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "username=admin' OR 1=1--&password=foo\r\n"
    )
    res_http = HTTPDecoder.decode_text_http1(smuggle_http)
    assert res_http.protocol == ProtocolType.HTTP1
    assert res_http.is_suspicious is True
    rule_ids = [a.rule_id for a in res_http.anomalies]
    assert "HTTP-SMUGGLE-001" in rule_ids
    assert "HTTP-SCANNER-001" in rule_ids
    assert "HTTP-SQLI-001" in rule_ids

    # 2. HTTP/2 Rapid Reset Attack Stream (Alternating HEADERS + RST_STREAM)
    h2_stream = bytearray()
    for stream_id in range(1, 15, 2):
        # HEADERS frame: length=4, type=0x01, flags=0x04, stream_id
        h2_stream += struct.pack("!BBBBBI", 0, 0, 4, 0x01, 0x04, stream_id) + b"\x82\x86\x84\x41"
        # RST_STREAM frame: length=4, type=0x03, flags=0x00, stream_id
        h2_stream += struct.pack("!BBBBBI", 0, 0, 4, 0x03, 0x00, stream_id) + struct.pack("!I", 0x08)

    res_h2 = HTTPDecoder.decode_binary_http2(bytes(h2_stream))
    assert res_h2.protocol == ProtocolType.HTTP2
    assert res_h2.is_suspicious is True
    assert any(a.rule_id == "HTTP2-RAPIDRESET-001" for a in res_h2.anomalies)


def test_tls_ja3_fingerprinting():
    """Verify TLS ClientHello parsing and JA3 calculation."""
    # Record Header: ContentType=0x16, Version=0x0303 (TLS 1.2), Length=50
    # Handshake: Type=0x01 (ClientHello), Length=46
    # ClientVersion=0x0303, Random (32B), SessionID Len=0, Ciphers Len=4 (0x1301, 0x1302), Comp Len=1, Ext Len=0
    rec_hdr = struct.pack("!BHH", 0x16, 0x0303, 48)
    hs_hdr = b"\x01" + struct.pack("!I", 44)[1:]
    client_ver = struct.pack("!H", 0x0303)
    random_bytes = b"\xAA" * 32
    sess_id = b"\x00"
    ciphers = struct.pack("!HHH", 4, 0x1301, 0x1302)
    comp = b"\x01\x00"
    exts = struct.pack("!H", 0)

    tls_pkt = rec_hdr + hs_hdr + client_ver + random_bytes + sess_id + ciphers + comp + exts
    res = TLSDecoder.decode_client_hello(tls_pkt)

    assert res.protocol == ProtocolType.TLS
    assert res.fingerprint is not None
    assert len(res.fingerprint) == 32  # MD5 JA3 hash


def test_smb_eternalblue_and_lateral_pipe():
    """Verify SMBv1 EternalBlue and SMBv2 lateral pipe detection."""
    # 1. SMBv1 with NT Transact command (0x25)
    smbv1_pkt = b"\x00\x00\x00\x30\xffSMB\x25\x00\x00\x00\x00" + b"\x00" * 40
    res_smb1 = SMBDecoder.decode(smbv1_pkt)
    assert res_smb1.is_suspicious is True
    assert any(a.rule_id == "SMB-ETERNALBLUE-001" for a in res_smb1.anomalies)

    # 2. SMBv2 with PsExec named pipe access
    # SMB2 Magic: \xFESMB (64-byte header)
    smb2_hdr = b"\xfeSMB" + b"\x40\x00\x00\x00\x00\x00\x00\x00\x05\x00" + b"\x00" * 50
    pipe_payload = "\\pipe\\psexesvc".encode("utf-16le")
    res_smb2 = SMBDecoder.decode(smb2_hdr + pipe_payload)
    assert res_smb2.is_suspicious is True
    assert any(a.rule_id == "SMB-LATERAL-PIPE-001" for a in res_smb2.anomalies)


def test_kerberos_roasting_detection():
    """Verify Kerberos TGS-REQ RC4 downgrade detection."""
    # Kerberos TGS-REQ tag: 0x6C, with ASN.1 INTEGER etype 23 (0x02, 0x01, 0x17)
    kerb_pkt = b"\x6c\x20\x30\x1e\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x0c\xa2\x12\x30\x10\x02\x01\x17"
    res = KerberosDecoder.decode(kerb_pkt)
    assert res.protocol == ProtocolType.KERBEROS
    assert res.is_suspicious is True
    assert any(a.rule_id == "KERB-ROASTING-001" for a in res.anomalies)


def test_rdp_insecure_and_bluekeep_detection():
    """Verify RDP connection request without NLA and BlueKeep signature."""
    # TPKT (0x03, 0x00, Len=35), X.224 CR (len=30, 0xE0), RDP Neg Req (0x01, 0x00, 0x08, 0x00, proto=0x00000000)
    tpkt = struct.pack("!BBH", 3, 0, 35)
    x224 = b"\x1e\xe0\x00\x00\x00\x00\x00"
    rdp_neg = b"\x01\x00\x08\x00\x00\x00\x00\x00"
    channel_binding = b"MS_T120"
    rdp_pkt = tpkt + x224 + rdp_neg + channel_binding

    res = RDPDecoder.decode(rdp_pkt)
    assert res.protocol == ProtocolType.RDP
    assert res.is_suspicious is True
    assert any(a.rule_id == "RDP-NO-NLA-001" for a in res.anomalies)
    assert any(a.rule_id == "RDP-BLUEKEEP-001" for a in res.anomalies)


def test_scada_modbus_and_dnp3_dissection():
    """Verify industrial OT decoders for Modbus TCP and DNP3."""
    # 1. Modbus TCP: TxID=1, Proto=0, Len=6, Unit=1, Function=0x5A (PLC Program)
    modbus_pkt = struct.pack("!HHHB", 1, 0, 6, 1) + b"\x5a\x00\x01\x02"
    res_mod = ModbusDecoder.decode(modbus_pkt)
    assert res_mod.protocol == ProtocolType.MODBUS
    assert res_mod.is_suspicious is True
    assert any(a.rule_id == "MODBUS-PLC-PROGRAM-001" for a in res_mod.anomalies)

    # 2. DNP3: Sync=0x0564, Len=5, Ctrl=0x44, Dst=10, Src=20, CRC=0, TrCtrl=0x00, AppCtrl=0x00, AppFn=0x15 (Disable Unsolicited)
    dnp3_hdr = b"\x05\x64" + struct.pack("<BBHHH", 5, 0x44, 10, 20, 0x1234)
    dnp3_app = b"\x00\x00\x15"
    res_dnp3 = DNP3Decoder.decode(dnp3_hdr + dnp3_app)
    assert res_dnp3.protocol == ProtocolType.DNP3
    assert res_dnp3.is_suspicious is True
    assert any(a.rule_id == "DNP3-DISABLE-UNSOLICITED-001" for a in res_dnp3.anomalies)


def test_bacnet_and_mqtt_dissection():
    """Verify smart building BACnet and IoT MQTT decoders."""
    # 1. BACnet/IP: Type=0x81, Fn=0x0A (Unicast), Len=10, NPDU=1,0, APDU Confirmed (type=0), Svc=0x1A (ReinitializeDevice)
    bacnet_pkt = struct.pack("!BBH", 0x81, 0x0A, 10) + b"\x01\x00\x00\x01\x02\x1a"
    res_bac = BACnetDecoder.decode(bacnet_pkt)
    assert res_bac.protocol == ProtocolType.BACNET
    assert res_bac.is_suspicious is True
    assert any(a.rule_id == "BACNET-REBOOT-001" for a in res_bac.anomalies)

    # 2. MQTT SUBSCRIBE with wildcard '#' eavesdropping
    # Byte 0: 0x82 (SUBSCRIBE, QoS 1), Remaining Len=6, PktID=1, Topic="#" (len 1, "#"), QoS=0
    mqtt_sub = b"\x82\x06\x00\x01\x00\x01\x23\x00"
    res_mqtt = MQTTDecoder.decode(mqtt_sub)
    assert res_mqtt.protocol == ProtocolType.MQTT
    assert res_mqtt.is_suspicious is True
    assert any(a.rule_id == "MQTT-WILDCARD-RECON-001" for a in res_mqtt.anomalies)


@pytest.mark.asyncio
async def test_protocols_rest_api():
    """Verify HTTP REST endpoints for DPI dissection, batch mode, and stats."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Login
        login_resp = await ac.post("/api/auth/login", json={"username_or_email": "superadmin", "password": "CyberShield2026!"})
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Get Supported Protocols
        res_supp = await ac.get("/api/protocols/supported", headers=headers)
        assert res_supp.status_code == 200
        assert "DNS" in res_supp.json()["supported_protocols"]
        assert "MODBUS" in res_supp.json()["supported_protocols"]

        # 2. Single Dissection via Hex
        # Modbus Write Coil
        hex_modbus = binascii.hexlify(struct.pack("!HHHB", 1, 0, 6, 1) + b"\x05\x00\x10\xff\x00").decode("ascii")
        res_dissect = await ac.post(
            "/api/protocols/dissect",
            json={"payload_hex": hex_modbus, "src_port": 40100, "dst_port": 502},
            headers=headers,
        )
        assert res_dissect.status_code == 200
        data = res_dissect.json()
        assert data["protocol"] == "MODBUS"
        assert data["decoded_packet"]["headers"]["function_name"] == "Write Single Coil"

        # 3. Batch Dissection
        batch_payload = {
            "packets": [
                {"payload_text": "GET /index.html HTTP/1.1\r\nHost: test.local\r\n\r\n", "dst_port": 80},
                {"payload_hex": hex_modbus, "dst_port": 502},
            ]
        }
        res_batch = await ac.post("/api/protocols/dissect/batch", json=batch_payload, headers=headers)
        assert res_batch.status_code == 200
        assert res_batch.json()["total_processed"] == 2

        # 4. Get DPI Stats
        res_stats = await ac.get("/api/protocols/stats", headers=headers)
        assert res_stats.status_code == 200
        assert res_stats.json()["total_dissected"] >= 2
