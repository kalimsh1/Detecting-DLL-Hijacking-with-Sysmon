# Detecting-DLL-Hijacking-with-Sysmon

## Overview
This repository demonstrates how to detect DLL Hijacking on Windows endpoints using **Sysmon Event ID 7 (Image Load)**.  
The lab simulates a real-world DLL hijacking attack using `calc.exe` and analyzes Sysmon telemetry to identify clear indicators of compromise (IOCs)

## Objective
- Simulate a DLL Hijacking attack
- Enable and tune Sysmon to capture Image Load events
- Analyze Sysmon Event ID 7
- Identify reliable IOCs for detection
- Understand how defenders can detect DLL hijacking in real environments

## Tools & Resources
- Windows 10
- Sysmon
- Sysmon configuration from SwiftOnSecurity  
  https://github.com/SwiftOnSecurity/sysmon-config
- Event Viewer
- Reflective DLL


In the case of detecting DLL hijacks, we change the "include" to "exclude" to ensure that nothing is excluded, allowing us to capture the necessary data.
![WhatsApp Image 2025-12-08 at 1 45 11 PM](https://github.com/user-attachments/assets/e86093ac-5538-4be8-be8e-72cee5335bf5)

![WhatsApp Image 2025-12-08 at 1 45 11 PM (4)](https://github.com/user-attachments/assets/770484b8-bb44-429d-ae9e-0414840c3068)


To utilize the updated Sysmon configuration, execute the following.

![WhatsApp Image 2025-12-08 at 1 45 11 PM (1)](https://github.com/user-attachments/assets/0450e409-74f8-4742-a0d1-11f851eb420a)


With the modified Sysmon configuration, we can start observing image load events. To view these events, navigate to the Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon." A quick check will reveal the presence of the targeted event ID.
![WhatsApp Image 2025-12-08 at 1 45 10 PM (1)](https://github.com/user-attachments/assets/2e399fc2-c7aa-4d40-bb86-b3f80775eb57)


Let's now see how a Sysmon event ID 7 looks like.
![WhatsApp Image 2025-12-08 at 1 45 09 PM (2)](https://github.com/user-attachments/assets/53da69f0-9510-42bd-9c20-ea1a5c7de529)


Let's attempt the hijack using "calc.exe" and "WININET.dll" as an example. To simplify the process, we can utilize Stephen Fewer's "hello world" : https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/bin


A writable directory (C:\Users\Administrator\Downloads\Meshari_DLL) is used to simulate a DLL hijacking attack.
The legitimate calc.exe binary is copied from System32, and a malicious DLL is renamed to WININET.dll and placed in the same directory.
![WhatsApp Image 2025-12-08 at 1 45 09 PM (1)](https://github.com/user-attachments/assets/e4dcfbaf-8abe-41cd-8871-081ccc8ea832)
![WhatsApp Image 2025-12-08 at 1 45 11 PM (3)](https://github.com/user-attachments/assets/f3417b19-c448-4fea-9a35-d2566fa691de)



Why this matters:
Windows follows a DLL search order. If a DLL with the expected name exists in the application directory, it will be loaded before the legitimate DLL in System32.


When calc.exe is executed from the writable directory, the malicious WININET.dll is loaded instead of the legitimate one.

Successful execution is confirmed by the appearance of a message box (Hello from DllMain!), proving code execution via DLL hijacking.
![WhatsApp Image 2025-12-08 at 1 45 09 PM (3)](https://github.com/user-attachments/assets/0d056282-6c0c-4e2f-854f-7a28cfdecb44)



Next, we analyze the impact of the hijack. First, we filter the event logs to focus on Event ID 7, which represents module load events, by clicking "Filter Current Log...".
![WhatsApp Image 2025-12-08 at 1 45 09 PM](https://github.com/user-attachments/assets/55e52e37-f8de-4776-8001-9dc51b836767)


Subsequently, we search for instances of "calc.exe", by clicking "Find...", to identify the DLL load associated with our hijack.
![WhatsApp Image 2025-12-08 at 1 45 10 PM (3)](https://github.com/user-attachments/assets/4974f23a-db81-4a38-94ea-3a54dd297443)


The output from Sysmon provides valuable insights. Now, we can observe several indicators of compromise (IOCs) to create effective detection rules. Before moving forward though, let's compare this to an authenticate load of "wininet.dll" by "calc.exe".


Identifying Malicious vs Legitimate Behavior
Malicious DLL Load (Hijacked)

Sysmon Event ID 7 shows:

calc.exe running from a user-writable directory

WININET.dll loaded from the same directory

DLL is unsigned

This behavior is abnormal and highly suspicious.
![WhatsApp Image 2025-12-08 at 1 45 10 PM (2)](https://github.com/user-attachments/assets/80141bca-547d-4f01-9fb9-4801cc083219)


Legitimate DLL Load

Comparison with legitimate behavior shows:

calc.exe running from C:\Windows\System32

WININET.dll loaded from System32

DLL is Microsoft-signed

This comparison confirms the anomaly.
![WhatsApp Image 2025-12-08 at 1 45 10 PM](https://github.com/user-attachments/assets/f062567c-dc2f-47ae-9f88-fb47174d30d0)


Let's explore these IOCs:

"calc.exe", originally located in System32, should not be found in a writable directory. Therefore, a copy of "calc.exe" in a writable directory serves as an IOC, as it should always reside in System32 or potentially Syswow64.

"WININET.dll", originally located in System32, should not be loaded outside of System32 by calc.exe. If instances of "WININET.dll" loading occur outside of System32 with "calc.exe" as the parent process, it indicates a DLL hijack within calc.exe. While caution is necessary when alerting on all instances of "WININET.dll" loading outside of System32 (as some applications may package specific DLL versions for stability), in the case of "calc.exe", we can confidently assert a hijack due to the DLL's unchanging name, which attackers cannot modify to evade detection.

The original "WININET.dll" is Microsoft-signed, while our injected DLL remains unsigned.

These three powerful IOCs provide an effective means of detecting a DLL hijack involving calc.exe. It's important to note that while Sysmon and event logs offer valuable telemetry for hunting and creating alert rules, they are not the sole sources of information.



