# SNS Attack Pi — Offensive Subsystem

## 1. Connecting to the Offensive Pi

Ensure you are connected to the **SNS WiFi**, then run the following in your command prompt:

```bash
ssh kali@192.168.0.174
```

Password: `kali`

The Offensive Pi will stay on after you leave. If it ever powers off, refer to **Section 1.1**.

---

### 1.1 Connecting to the Offensive Pi After Powering On

When the Pi powers on, it defaults to running the Layer 2 deauthentication attack on startup, which disables networking features. This means SSH is not available until networking is manually re-enabled. You have two options to gain initial access:

**Option 1 — Monitor, keyboard, and mouse (easiest)**
Connect peripherals directly to the Pi and log in. Password: `kali`

**Option 2 — Ethernet cable from your laptop to the Pi**
Change your laptop's ethernet port IP address to `172.168.1.25`, then run:

```bash
ssh kali@172.168.1.24
```

---

### 1.2 Enabling Networking Features After Startup

> Networking must be enabled to use Layer 3–5 attacks. Disabling it locks the Pi into Layer 2 (deauthentication) only.

Once logged in via Option 1 or Option 2, navigate to the Documents folder and check your interfaces:

```bash
cd Documents
iwconfig
```

The `iwconfig` output will show one ethernet interface (`eth0`) and two wireless interfaces (`wlan0` and `wlan1`). The Pi has one built-in wireless interface and one external TP-Link Wireless Transceiver connected via USB. Find whichever WLAN shows `Nickname:"WIFI@RTL8821AU"` — this is the transceiver. The interface name may change between boots, so always check.

Then run the networking script using that interface:

```bash
./turn_on_networking.sh wlan0
# or, if the transceiver was identified as wlan1:
./turn_on_networking.sh wlan1
```

---

### 1.2.1 Running the Attack GUI

Navigate to the L5 directory and launch the GUI:

```bash
cd ~/L5
python3 gui0.py
```

The terminal will print a URL. Hold `Ctrl` and left-click `http://192.168.0.174:5000` to open the dashboard in your browser.

> **Note:** That URL only works when connected to the SNS router. To test on RaspAP WiFi, connect the Offensive Pi to RaspAP first, re-run `gui0.py`, then `Ctrl+click` the `10.3.141.x` URL printed in the terminal instead.

**To run an attack:**
1. Select an attack from the **Select Attack** box
2. Adjust the parameter values to your needs
3. Click **Run Attack**

Output will appear in the **Output Log** section at the bottom of the page.

**To capture traffic:**
1. Click **Start Capture** before launching the attack
2. Run the attack
3. Stop the attack, then click **Stop Capture**
4. The **Analysis** section will appear with traffic metrics

The four main attacks are covered in Sections 1.2.2 through 1.2.5.

---

### 1.2.2 Deauthentication Attack — Layer 2

This attack sends 802.11 deauthentication frames that disconnect all devices from the target WiFi network. **Use with caution** — the SNS router has built-in protections that resist this attack. For testing purposes, switch all devices (controller and robot) to the RaspAP network first.

| Parameter | Description |
|---|---|
| Interface | Must be the TP-Link transceiver interface. Run `iwconfig` and use whichever WLAN shows `Nickname:"WIFI@RTL8821AU"` |
| Target SSID | The network to attack. Use `RaspAP` for testing. |
| Packets/sec | Flood rate. Set to `0` for unlimited. |

---

### 1.2.3 ICMP Flood — Layer 3

Floods the target with ICMP Echo Request (ping) packets, consuming bandwidth and processing resources on the victim device.

| Parameter | Description |
|---|---|
| Target IP | IP address of the robot |
| Send Mode | `Flood` for unlimited speed, `Count` for a fixed packet burst |

---

### 1.2.4 TCP SYN Flood — Layer 4

Floods a specific port on the target with TCP SYN packets, exhausting the connection table and degrading or blocking service on that port.

| Parameter | Description |
|---|---|
| Target IP | IP address of the robot |
| Target Port | Port to flood. `22` = SSH, `80` = HTTP, `443` = HTTPS |
| Send Mode | `Flood` for unlimited speed, `Count` for a fixed packet burst |

---

### 1.2.5 ROS2 Dynamic Man-in-the-Middle Attack — Layer 5

Intercepts velocity command packets being sent from the controller to the robot, allowing the attacker to observe or modify movement commands in real time. The controller must already be running a script that moves the robot before launching this attack. Refer to the **Controller: Ubuntu** section for instructions on running robot movement scripts.

| Parameter | Description |
|---|---|
| Robot IP | IP address of the robot |
| Controller IP | IP address of the controller |
| Interface | Wireless interface to intercept traffic on |
| Linear / Angular Speed | Replacement velocity values injected into intercepted packets |

---

#### 1.2.5.1 MITM Attack with Manual Keyboard Control

This variant of the MITM attack lets you take full keyboard control of the robot by intercepting and replacing its velocity commands in real time. This is run entirely from the terminal — the GUI is not used.

**Step 1 — Make sure the robot is running from the controller.**
Refer to the UbuntuVM section for instructions.

**Step 2 — On the Offensive Pi, connect to SNS WiFi and navigate to L5:**

```bash
cd ~/L5
```

**Step 3 — Set up IP forwarding and the netfilter queue:**

```bash
sudo iptables -I FORWARD -s [controller_ip] -d [robot_ip] -j NFQUEUE --queue-num 1
sudo sysctl -w net.ipv4.ip_forward=1
```

**Step 4 — Update the IP addresses in the intercept script:**

```bash
nano test3_og.py
```

Find the section that defines `robot_ip` and `controller_ip` and update both values to the actual IP addresses.

**Step 5 — Run the script:**

```bash
sudo python3 test3_og.py
```

After a few seconds, output will confirm the intercept is active. You can now use the keyboard to control the robot manually.

---

## 2. Adding a New Attack to the GUI

This section explains how to add a new attack to `gui0.py`. The dashboard is data-driven, meaning every attack is defined in one place and the GUI builds itself from that definition. You will need to make changes in **five locations** inside `gui0.py`. All five must be consistent with each other, or the live command preview and the actual executed command will disagree.

---

### 2.1 Define the Attack in the `ATTACKS` List

Near the top of `gui0.py` there is a Python list called `ATTACKS`. Each entry is a dictionary that defines everything about one attack — its label, category, color, and all of its configurable fields. Add a new dictionary to this list following the same structure as the existing four attacks.

A minimal example:

```python
{
    "id":          "your_attack_id",
    "label":       "Your Attack Name — tool (Layer X)",
    "description": "One or two sentences describing what this attack does.",
    "category":    "Layer X / DoS",
    "color":       "#HEXCOLOR",
    "params": [
        {
            "id":          "ip",
            "label":       "Target IP",
            "type":        "text",
            "default":     "",
            "placeholder": "192.168.x.x",
            "required":    True,
        },
        {
            "id":      "port",
            "label":   "Target Port",
            "type":    "number",
            "default": "80",
            "min":     1,
            "max":     65535,
            "hint":    "80=HTTP · 443=HTTPS · 22=SSH",
        },
    ],
},
```

**Field reference for each param:**

| Key | Required | Description |
|---|---|---|
| `id` | Yes | Snake_case identifier. Must be unique within this attack's params. |
| `label` | Yes | Display name shown above the input in the GUI. |
| `type` | Yes | One of: `text`, `number`, `select`, `checkbox` |
| `default` | Yes | Pre-filled value when the attack is first selected. |
| `placeholder` | No | Hint text inside the input when empty. |
| `hint` | No | Small grey help text shown below the field. |
| `required` | No | Set `True` to block launch if the field is empty. Fields with `id: "ip"` also trigger IPv4 format validation automatically. |
| `min` / `max` | No | Number fields only. Enforced both in the browser and server-side. |
| `options` | No | Select fields only. List of `{"value": "x", "label": "Display Name"}` dicts. |
| `depends_on` | No | Hides this field unless another param matches a value. Example: `{"mode": "count"}` hides this field unless the `mode` param is set to `"count"`. |

**Important:** The `id` string you pick here is what connects this entry to all four of the locations below. It must match exactly everywhere.

---

### 2.2 Add a Branch to `build_command()` (Python)

`build_command()` takes the attack id and a dict of param values and returns the full shell command string that gets executed on the Pi. Find this function and add an `if` block for your new attack.

```python
if atk_id == "your_attack_id":
    cmd = f"sudo yourtool --flag {p.get('param_id', 'fallback')}"
    if p.get("optional_flag", "") not in ("", "0"):
        cmd += f" --optional {p['optional_flag']}"
    return f"{cmd} {p['ip']}"   # target IP always goes last
```

Rules to follow:
- Use `p.get("key", "fallback")` instead of `p["key"]` so missing optional params don't crash
- Always put the target IP at the end of the command as a positional argument — this is correct syntax for hping3 and most tools
- Include `sudo` at the start if the tool requires root
- Return the command as a single string — the route calls `shlex.split()` on it before passing to `subprocess.Popen`

---

### 2.3 Add a Branch to `validate_params()` (Python)

`validate_params()` runs on the server before `build_command()` is ever called. It is the last line of defense after the browser-side checks. Add an `elif` block that returns a plain error string if something is wrong, or `None` if everything is valid.

```python
elif atk_id == "your_attack_id":
    if not _valid_ip(p.get("ip", "")):
        return "Invalid target IP"
    try:
        port = int(p.get("port", ""))
        if not (1 <= port <= 65535):
            raise ValueError
    except Exception:
        return "Port must be 1–65535"
```

Two helper functions are already defined in the file for you to reuse:
- `_valid_ip(ip)` — returns `True` if the string is a valid IPv4 address
- `_int_in_range(val, lo, hi)` — returns `True` if the string converts to an int within the given range

The error string you return is sent directly to the browser as a red log line, so write it as a clear human-readable sentence.

---

### 2.4 Add a Branch to `buildCmd()` (JavaScript)

`buildCmd()` is the JavaScript mirror of `build_command()`. It runs on every keypress and dropdown change to update the live command preview at the bottom of the Parameters card. It must produce the exact same output as the Python function for the same inputs.

Find this function in the `<script>` block near the bottom of the `PAGE` string and add an `if` block:

```javascript
if (id === 'your_attack_id') {
    let cmd = 'sudo yourtool --flag ' + (vals.param_id || 'fallback');
    if (vals.optional_flag && vals.optional_flag !== '0') {
        cmd += ' --optional ' + vals.optional_flag;
    }
    return cmd + ' ' + (vals.ip || '<target-ip>');
}
```

Notes:
- Pull values from the `vals` object, which holds the current state of all param fields
- Use `|| 'fallback'` the same way Python uses `.get()` with a fallback
- For checkbox params, `vals.param_id` will be the boolean `true` or `false`, not a string — check it with `if (vals.param_id)` not `if (vals.param_id === 'true')`
- `'<target-ip>'` is the placeholder shown in the preview when the IP field is empty

---

### 2.5 Add a Branch to `autoFilter()` (JavaScript)

`autoFilter()` generates a BPF filter string for the tshark capture card when the user clicks the "Auto-fill" button. Find this function and add an `else if` block for your attack:

```javascript
else if (atk.id === 'your_attack_id') {
    f = 'tcp and host ' + vals.ip + ' and port ' + vals.port;
}
```

Common BPF patterns:
- ICMP-based attack: `'icmp and host ' + vals.ip`
- TCP-based attack: `'tcp and host ' + vals.ip + ' and port ' + vals.port`
- Wireless frame attack: `'wlan type mgt subtype deauth'`
- Passive/general capture: `'not arp and not broadcast'`

If you skip this step the auto-fill button will produce an empty filter for your attack, which is not harmful but unhelpful.

---

### 2.6 Checklist Before Testing

Go through this before running `python3 gui0.py`:

- [ ] The `id` string in the `ATTACKS` entry exactly matches the string in all four `if/elif/else if` blocks
- [ ] Every param `id` referenced in `build_command()` and `buildCmd()` matches a param `id` defined in the `ATTACKS` entry
- [ ] Any param with `depends_on` references another param `id` that actually exists in the same attack's params list
- [ ] Python `build_command()` and JavaScript `buildCmd()` produce the same command for the same inputs
- [ ] The binary being called is installed on the Pi — the output log will show a red "Tool not found" error if it is not
- [ ] `sudo` is included in the command string if the tool requires root

---

### 2.7 Summary of All Five Locations

| Location | Language | What You Add |
|---|---|---|
| `ATTACKS` list | Python | Full attack dict with id, label, description, category, color, and params |
| `build_command()` | Python | `if atk_id ==` branch that returns the shell command string |
| `validate_params()` | Python | `elif atk_id ==` branch that returns an error string or `None` |
| `buildCmd()` | JavaScript | `if (id === )` branch that returns the same command for the live preview |
| `autoFilter()` | JavaScript | `else if (atk.id === )` branch that sets the BPF filter string |
