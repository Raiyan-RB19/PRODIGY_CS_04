## Keylogger  App (Local & Remote)

A Python-based GUI keylogger app with two powerful modes:

  - Personal Mode – Record and save keystrokes locally on your own device.

   - External Mode – Log keystrokes from a remote client PC over a network.

All within a single, user-friendly interface.
 ## Features

  - Personal Mode: Capture keystrokes locally and save them to a file with timestamps.

- External Mode (Server): Host a server that receives keystrokes live from other devices.

- Remote Client Mode: Send keystrokes to a server in real time.

 - Logs saved with full timestamps.

  - Built with Python, Tkinter (GUI), sockets, and pynput.

## Requirements

Install required Python packages:
```
pip install pynput
```
If running on Linux (like Kali):
```
sudo apt install python3-tk
```
Run the app:
```
python3 main.py
```

## Remote Logging Setup

   - Server PC: Run the app, go to External Mode, click Start Server.

   - Client PC: Run the app, go to Remote Client Mode, enter the server's IP and click Start Sending.

-  Keystrokes will be sent live to the server window.

## Current Ethical Rules in the Program

  #### Client Consent Prompt

  - Before starting keylogging in Remote Client Mode, the app shows a confirmation popup:

            “Allow this tool to send your keystrokes to the server?”

 -  This ensures that the client is notified and gives explicit consent before their keystrokes are sent.

  #### No Hidden Execution

  - The program does not run in the background or hide from the user.

   -  It uses a visible GUI, making its function clear to the user at all times.

  #### Manual Connection to Server

   -  The client must manually enter the IP address and start the connection.

  -  This prevents secret or automated connections to unknown servers.

 #### Clear Start/Stop Controls

  - Both client and server modes include "Start" and "Stop" buttons, so the user can control when logging begins and ends.

 #### Local Logs Only When Chosen

  - In Personal Mode, keystrokes are saved locally only if the user starts logging manually.

## Ethical Notice

   This tool is for educational and ethical use only. Do NOT use it without explicit permission from the device owner.
  Unauthorized use may violate laws in your country or region. You are solely responsible for your actions.
