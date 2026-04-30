1. Connecting to the Offensive Pi 
Type in this command in your command prompt “ssh kali@192.168.0.174”. The password is “kali”. Make sure you’re connected to SNS wifi. The Offensive Pi will stay on after we leave. If the offensive pi ever turns off, refer to 4.1.1 to see how to connect to the offensive pi again. 

Figure 25: Using SSH to connect to Offensive Pi

1.1 Connecting to the Offensive Pi After Powering On
Whenever the Offensive Pi ever turns off, powering it on again disables any networking features on startup since it defaults to start attacking on Layer 2 first (deauthentication attack). That means ssh isn’t available on startup. So there are two ways to access and login to the offensive pi initially
Connect a monitor, keyboard, and mouse
Use an ethernet cable from your laptop to pi
Option 1 is the easiest way to connect to pi. Password is “kali”. Option 2 requires you to change the IP address of your laptop’s ethernet port. If you do decide to go with option 2, change your ip address of your ethernet port to 172.168.1.25. Open command prompt and type in “ssh kali@172.168.1.24”. 


1.2 Enabling Networking Features After Startup
Enabling networking features allows you to use Layer 3 - Layer 5 attacks. But disabling it allows you to use Layer 2 attack (deauthentication attack).
Once you have access to the offensive pi by either Option 1 or Option 2, change directories to the Documents folder by typing “cd Documents”. Then run “iwconfig”.

Figure 26: iwconfig Output

The iwconfig command gives more information on the different interfaces. There is one ethernet interface, “eth0”, and two wireless interfaces, “wlan0” and “wlan1”. The reason why there’s two wireless interfaces is because there’s one wireless interface already built in the Raspberry Pi, while the other wireless interface is the TP Link Wireless Transceiver connected to one of the USB ports. Take note of which WLAN has a Nickname:”WIFI@RTL8821AU”. In this case, it’s wlan0. But on startup, it may change. Then run this command “./turn_on_networking.sh [wlan1 or wlan2]”. In this case, you would run “./turn_on_networking.sh wlan0”. But if wlan1 had the Nickname:”WIFI@RTL8821AU”, you would instead run “./turn_on_networking.sh wlan1”.

1.2.1 How To Run Each Attack 
A python script was made to open up a GUI in your web browser to be able to easily test with attacks. Ensure that you’re in the L5 directory with “cd ~/L5”. Then run “python3 gui0.py”. This will pop up a terminal output as shown below. 

Figure 27: Output of gui0.py

Press left control plus left click on http://192.168.0.174:5000 to visit the GUI. The dashboard will look like this. Note: that website will only work for when you’re connected to the SNS router. If you want to test these on the RaspAP wifi, connect the offensive pi to RaspAP, then run the gui0.py script. Then press control plus left click on the 10.3.141.x website.

Figure 28: Offensive GUI 
The main attacks to focus on is Deauth Flood (Layer 2), ICMP Flood (Layer 3), TCP SYN Flood (Layer 4), and ROS2 Dynamic MitM (Layer 5). 

To attack with a specific attack, choose one of the options in the Select Attack Box, change specific parameter values to your needs, and click Run Attack. 

There should be some output shown in the output log box once you click run.

Figure 29: Offensive GUI Output Log Section

There’s also a Start Capture feature in the dashboard which allows you to analyze the traffic of the attack. Make sure to press the Start Capture button before the attack, and stop the packet capture after stopping the attack. The Analysis box should pop up and show some metrics.

Figure 30: Offensive GUI Analysis Section

1.2.2 Deauthentication Attack | Layer 2

Figure 31: Deauthentication Attack Diagram

For the deauthentication attack, it disconnects all devices from the wifi so be careful when using this. The SNS router has built in security that doesn’t easily allow this to happen. But if you want to test this attack for testing purposes, switch to the RaspAP wifi for all devices: controller and robot. There are 3 important parameters: interface, target ssid, and packets/sec. For interface, you want to make sure you’re attacking through the wireless transceiver interface. To see which interface that is, type in “iwconfig” in the terminal and check which one has Nickname:”WIFI@RTL8821AU”. Use that interface. For the target SSID, choose which wifi you want to attack. Use RaspAP in this case. And for packets/sec, you can customize that to how you want. 


Figure 32: Deauthentication Attack Parameters

1.2.3 ICMP Flood | Layer 3

Figure 33: ICMP Flood Diagram

This attack floods Layer 3 with ICMP ping packets, which takes up resources and causes disruption. The target IP should be the robot IP. And for the send mode, there’s a drop down where you can select which speed you want.

Figure 34: ICMP Flood Parameters
 
1.2.4 TCP SYN Flood

Figure 35: TCP SYN Flood Diagram
This attack floods a specific application through a specific port number. It has similar parameters to the ICMP flood, but this time, you can specify the port number. In this example, port 22 corresponds to SSH. So SSH sessions will feel a bit slow, as well as other services on the robot.

Figure 36: TCP SYN Flood Parameters

1.2.5 ROS2 Dynamic Man in the Middle Attack | Layer 5

Figure 37: Man In The Middle Attack Diagram
This attack intercepts the packets being sent from the controller to the robot when sending velocity commands. Parameters include ip address from the robot and controller, wireless interface, as well as linear and angular speeds. The controller needs to be running a script that makes the robot run in a programmed behavior. Refer to the Controller: Ubuntu Section to run a script that runs the robot.

Figure 38: Man In The Middle Parameters

1.2.5.1 Man in the Middle Attack with Keyboard Control 
Another set of commands allow for full keyboard control of the robot in this Man in the Middle attack. This is done without the GUI, only terminal commands. 

First, make sure the robot is running from the controller. Refer to the UbuntuVM section to learn how to make a robot move.  

Then on the offensive pi, ensure that you’re connected to the SNS wifi first. Change directory to /L5. Then run these 2 commands on the terminal first. 

sudo iptables -I FORWARD -s [controller ip]-d [robot target ip]-j NFQUEUE --queue-num 1 
sudo sysctl -w net.ipv4.ip_forward=1

You will also need to change one more file. Type this command to edit a file called test3_og.py

nano test3_og.py

A text editor will show up in the terminal. Find a section in the code that looks like this.


Figure 39: test3_og.py IP Addresses Section

Make sure to update robot_ip and controller_ip to their actual IP addresses.

Finally, run test3_og.py.

sudo python3 test3_og.py

It will take a couple seconds, but an output will show up that looks similar to this.

Figure 40: Output of test3_og.py

At this point, you can use the keyboard to control the robot manually. 

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
