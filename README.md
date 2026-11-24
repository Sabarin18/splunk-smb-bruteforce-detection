# Home SOC Lab — SMB Brute-Force Detection & Triage | Splunk

## Objective

Built a hands-on home lab to practice how a Tier-1 SOC (Security Operations Center) analyst catches someone trying to guess passwords on a computer. By connecting a Kali Linux attacker computer (`192.168.1.12`) to a Windows 10 computer (`192.168.1.16`, `DESKTOP-AP7DMSG`) watched by Splunk Enterprise, this project shows the full story—from checking if the door is open, to knocking with wrong passwords, to catching the attacker in the security logs.

### Skills Learned

- **Checking If the Door Is Open (Network & Port Check):** Used `nmap -Pn` to find the Windows computer even when it ignores basic ping checks, and saw that SMB port `445` (`microsoft-ds`) was open.
- **Pretending to Be an Attacker (Adversary Emulation):** Used NetExec (`nxc`) on Kali Linux to rapid-fire wrong passwords at the Windows computer over SMB so Windows would record failed login warnings.
- **Finding Where Logs Live (SIEM Log Ingestion):** Opened Splunk Enterprise and checked where Windows saved the failed login logs (`EventCode=4625`), finding them inside the `main` index (`WinEventLog:Security`).
- **Pulling Out Clues with `rex` (Log Parsing):** Wrote a simple Splunk search using `rex` to pull out two key clues from messy log text—who was targeted (`TargetUserName`) and where the attack came from (`IpAddress`)—and counted the tries with `stats`.
- **Spotting the Real Attacker (Alert Triage):** Filtered for computers that failed `5` or more times (`failed_attempts >= 5`) and opened a full log to read the exact clue details needed to report the attack.

### MITRE ATT&CK Mapping

- **Tactics (What the attacker wants to do):**
  - **TA0006 — Credential Access:** Guessing passwords to break into an account.
  - **TA0008 — Lateral Movement:** Trying to connect to shared folders or services across the network using SMB.
- **Techniques (How the attacker does it):**
  - **T1110.001 — Brute Force: Password Guessing:** Trying many passwords quickly to find the right one.
  - **T1021.002 — Remote Services: SMB/Windows Admin Shares:** Knocking on Windows file-sharing port `445` to log in remotely.

### Tools Used

- **Splunk Enterprise:** The security dashboard (SIEM) that collects Windows logs, searches them, and helps spot suspicious logins.
- **Windows 10 Target (`DESKTOP-AP7DMSG`):** The target computer (`192.168.1.16`) with SMB port `445` open that writes a warning (`EventCode=4625`) every time a login fails.
- **Kali Linux, Nmap & NetExec (`nxc`):** The testing computer (`192.168.1.12`) used to check if port `445` is open and run the password-guessing test.
- **VirtualBox:** The software that runs both virtual computers safely on one machine.

## Steps

**Step 1: Check If the Target Computer's SMB Door Is Open**  
From Kali Linux (`192.168.1.12`), ran Nmap with `-Pn` (which skips the normal ping check in case a firewall blocks it) to see if Windows 10 (`192.168.1.16`) had SMB port `445` open. Nmap showed `445/tcp open microsoft-ds`, meaning the SMB door was open.

<img src="https://github.com/user-attachments/assets/b49903c5-3c77-4f6a-8c99-55e4fff82197" width="804" height="327" alt="Kali Linux Nmap Scan Confirming TCP Port 445 Open on Target">

Ref 1: Kali Linux terminal showing `nmap -Pn -p 445 192.168.1.16` confirming port `445/tcp` is open (`microsoft-ds`).

---

**Step 2: Run the Password-Guessing Test (`nxc`)**  
From Kali Linux (`192.168.1.12`), used NetExec (`nxc`) to test passwords against Windows 10 (`192.168.1.16`) over SMB. Each wrong password showed `STATUS_LOGON_FAILURE` on Kali and made Windows save a failed login record (`EventCode=4625`).

<img src="https://github.com/user-attachments/assets/34c90bd0-849c-45fb-9306-16ec92f234e6" width="1520" height="144" alt="NetExec SMB Brute-Force Execution from Kali Linux">

Ref 2: Kali Linux terminal running `nxc smb` against `192.168.1.16` and showing failed password attempts.

---

**Step 3: Find the Failed Login Logs in Splunk (`EventCode=4625`)**  
Opened Splunk Web on `DESKTOP-AP7DMSG` (`http://127.0.0.1:8000`), set the time filter to **All time**, and checked which storage bucket (index) held the `4625` logs (`index=* 4625 | stats count by index sourcetype`). Found all logs inside the `main` index under `WinEventLog:Security`, then searched `index=main EventCode=4625` to view all `57` failed login events.

<img src="https://github.com/user-attachments/assets/d9b1f376-3a87-4f20-82c8-ccad2a947bda" width="1009" height="718" alt="Splunk Search Events Tab Showing EventCode 4625 Logs">

Ref 3: Splunk Search **Events** tab set to **All time** showing `EventCode=4625` logs on `DESKTOP-AP7DMSG` (`source=WinEventLog:Security`).

---

**Step 4: Pull Out the Attacker IP and Username (`rex` & `stats`)**  
Ran a Splunk query over **All time** (`57 events`) using `rex` to grab the username (`TargetUserName`) and source IP (`IpAddress`) from each raw log, then used `stats` to count the failures:

```spl
index=main EventCode=4625
| rex field=_raw "Account Name:\s+(?<TargetUserName>\S+)"
| rex field=_raw "Source Network Address:\s+(?<IpAddress>\S+)"
| stats count by IpAddress TargetUserName
```

<img width="1007" height="715" alt="Splunk Statistics Tab Showing Extracted IpAddress and TargetUserName" src="https://github.com/user-attachments/assets/7f04bb4a-6b1f-4188-8f44-da4f3d363765" />
Ref 4: Splunk **Statistics** tab listing each `IpAddress`, `TargetUserName`, and failure `count` (including `192.168.1.12`).

---  

**Step 5: Catch High-Count Attackers (`failed_attempts >= 5`)**  
Filtered the search to the **Last 24 hours** (`12` events) and added a threshold rule (`where failed_attempts >= 5`) so Splunk isolates the active brute-force source (`192.168.1.12` with `12` failed attempts):
- **Event Code:** `4625` (An account failed to log on).
- **Source IP (Attacker Attribution):** `192.168.1.12` (Kali Linux attacker machine).
- **Failed Attempts (Last 24 Hours):** `12` consecutive failed authentication attempts over SMB.

```spl
index=main EventCode=4625
| rex field=_raw "Account Name:\s+(?<TargetUserName>\S+)"
| rex field=_raw "Source Network Address:\s+(?<IpAddress>\S+)"
| stats count as failed_attempts values(TargetUserName) as targeted_users by IpAddress
| where failed_attempts >= 5

```
<img width="1002" height="714" alt="Splunk Threshold Triage Showing 192.168.1.12 With 12 Failed Attempts" src="https://github.com/user-attachments/assets/60238aac-a578-4bba-8c92-85b2c95c0a88" />
Ref 5: Splunk **Statistics** tab filtered to the **Last 24 hours** isolating `192.168.1.12` with `12` failed attempts.

