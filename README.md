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
