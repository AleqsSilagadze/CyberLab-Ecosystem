
## Overview / მიმოხილვა

**EN:** CyberLab is an educational simulation environment built to help cybersecurity students and practitioners understand the full lifecycle of a cyberattack — from initial reconnaissance through lateral movement and impact — while simultaneously training blue-team analysts to detect, log, and respond to those events in real time.

**KA:** CyberLab არის საგანმანათლებლო სიმულაციის გარემო, შექმნილი კიბერუსაფრთხოების სტუდენტებისა და პრაქტიკოსებისთვის. პლატფორმა ასახავს კიბერშეტევის სრულ ციკლს — დაზვერვიდან დაწყებული, ლატერალური მოძრაობით გამავლობით, ზემოქმედების ეტაპამდე — და პარალელურად ამზადებს blue-team ანალიტიკოსებს ამ მოვლენების გამოვლენის, ჩაწერისა და მათზე რეაგირებისთვის.

---

## Architecture / არქიტექტურა

```
┌─────────────────────────────────────────────┐
│              CyberLab v3.0                  │
│                                             │
│   [network.py]          [server.py]         │
│   Red Team Client  ───► SOC Monitor         │
│   (Attacker Node)  UDP  (Forensic Server)   │
│                                             │
│          └────── [Hard.json] ───────┘       │
│               Scenario Engine               │
└─────────────────────────────────────────────┘
```

---

## Core Components / ძირითადი კომპონენტები

### 1. `network.py` — Red Team Network Emulator

**EN:** A Python-based offensive client that simulates the behavior of industry-standard red-team tools within a sandboxed environment. It generates realistic forensic footprints without interacting with live infrastructure.

**KA:** Python-ზე დაფუძნებული შეტევითი კლიენტი, რომელიც სიმულირებს სტანდარტული red-team ინსტრუმენტების ქცევას იზოლირებულ გარემოში. ის ქმნის რეალისტურ ფორენზიკულ კვალს რეალურ ინფრასტრუქტურაზე ზემოქმედების გარეშე.

Simulated tool behaviors:
- **Nmap-style** host discovery and port scanning
- **Metasploit-style** exploitation module chains
- **Shodan-style** passive reconnaissance queries
- **Hashcat-style** credential cracking simulation

---

### 2. `server.py` — SOC Monitor (Forensic Server)

**EN:** A real-time UDP-based server that acts as a Security Operations Center (SOC) console. It receives broadcasted events from the red team client, classifies alert severity, and maintains a structured attack timeline for post-exercise analysis.

**KA:** რეალურ დროში მომუშავე UDP-ზე დაფუძნებული სერვერი, რომელიც ასრულებს უსაფრთხოების ოპერაციების ცენტრის (SOC) კონსოლის როლს. ის იღებს red team კლიენტის მიერ გამოგზავნილ მოვლენებს, ახდენს შეტყობინებების სიმძიმის კლასიფიკაციას და ინარჩუნებს სტრუქტურირებულ შეტევის ვადებს სავარჯიშოს შემდგომი ანალიზისთვის.

Key capabilities:
- Non-blocking UDP event ingestion
- Alert level tracking (INFO / WARNING / CRITICAL)
- Real-time attack timeline reconstruction
- EDR/SIEM behavior emulation

---

### 3. `Hard.json` — Scenario Engine

**EN:** A JSON-driven configuration file that defines the network topology, target hosts, vulnerable services, and attack paths for each training scenario. Scenarios range from simple DMZ penetration to full Active Directory compromise chains.

**KA:** JSON-ზე დაფუძნებული კონფიგურაციის ფაილი, რომელიც განსაზღვრავს ქსელის ტოპოლოგიას, სამიზნე ჰოსტებს, დაუცველ სერვისებსა და თავდასხმის მარშრუტებს თითოეული სატრენინგო სცენარისთვის. სცენარები მოიცავს DMZ-ის მარტივი გარღვევიდან Active Directory-ის სრული კომპრომეტირების ჯაჭვებამდე.

---

## Technical Depth / ტექნიკური სიღრმე

### Forensic Logging / ფორენზიკული ჟურნალირება

**EN:** Every simulated action is broadcast to the SOC server via non-blocking UDP, mirroring how Endpoint Detection and Response (EDR) and Security Information and Event Management (SIEM) systems generate and transmit telemetry in production environments.

**KA:** ყოველი სიმულირებული მოქმედება გადაიცემა SOC სერვერზე არაბლოკირებადი UDP-ის საშუალებით, რაც ასახავს EDR და SIEM სისტემების მიერ ტელემეტრიის გენერირებისა და გადაცემის რეალურ პრინციპებს.

---

### Industrial Control Systems (ICS/SCADA) / სამრეწველო საკონტროლო სისტემები

**EN:** The simulator includes dedicated logic for Operational Technology (OT) environments, covering two widely-deployed industrial protocols:

- **Modbus** — common in power grids, water treatment, and manufacturing PLCs
- **S7comm** — Siemens S7 PLC communication protocol, prevalent in critical infrastructure

**KA:** სიმულატორი მოიცავს ოპერაციული ტექნოლოგიების (OT) გარემოსთვის განკუთვნილ სპეციალიზებულ ლოგიკას, ორი ფართოდ გამოყენებული სამრეწველო პროტოკოლისთვის:

- **Modbus** — გამოიყენება ელექტრო ქსელებში, წყლის გამწმენდ სადგურებსა და წარმოების PLC-ებში
- **S7comm** — Siemens S7 PLC-ის კომუნიკაციის პროტოკოლი, გავრცელებული კრიტიკულ ინფრასტრუქტურაში

---

### Complex Attack Paths / კომპლექსური შეტევის მარშრუტები

**EN:** The simulator covers advanced Active Directory attack techniques used in real-world red team engagements:

| Technique | Description |
|-----------|-------------|
| **Kerberoasting** | Simulates SPN enumeration and offline ticket cracking to compromise service accounts |
| **DCSync** | Emulates credential replication attacks against domain controllers |
| **Lateral Movement** | Models pass-the-hash, pass-the-ticket, and WMI/SMB-based pivoting across segments |

**KA:** სიმულატორი მოიცავს Active Directory-ის გაფართოებული შეტევის ტექნიკებს, რომლებიც გამოიყენება რეალური red team ოპერაციებში:

| ტექნიკა | აღწერა |
|---------|--------|
| **Kerberoasting** | სიმულირებს SPN-ის ჩამოთვლასა და offline ბილეთის გატეხვას სერვისული ანგარიშების კომპრომეტირებისთვის |
| **DCSync** | ახდენს სერთიფიკატების რეპლიკაციის შეტევების ემულაციას დომეინ კონტროლერებზე |
| **Lateral Movement** | მოდელირებს pass-the-hash, pass-the-ticket და WMI/SMB-ზე დაფუძნებულ გადაადგილებას სეგმენტებს შორის |

---

## Target Environments / სამიზნე გარემოები

| Zone | Description / აღწერა |
|------|----------------------|
| **DMZ** | Perimeter hosts, exposed web services, bastion nodes |
| **Corporate** | Internal AD, file servers, workstations, VPN endpoints |
| **OT/SCADA** | PLCs, HMIs, historians, industrial network segments |

---

## Getting Started / დაწყება

```bash
# Clone the repository
git clone https://github.com/your-org/cyberlab-v3.git
cd cyberlab-v3

# Install dependencies
pip install -r requirements.txt

# Start the SOC Monitor (Blue Team)
python server.py

# In a separate terminal, launch the scenario
python network.py --scenario Hard.json
```

---

## Project Structure / პროექტის სტრუქტურა

```
cyberlab-v3/
├── network.py          # Red team simulation client
├── server.py           # SOC forensic monitor
├── Hard.json           # Advanced scenario configuration
├── scenarios/          # Additional scenario files
├── logs/               # Generated attack timelines
├── requirements.txt
└── README.md
```

---

## Learning Objectives / სასწავლო მიზნები

**EN:**
- Understand the full kill chain from reconnaissance to impact
- Recognize forensic artifacts generated by common attack techniques
- Practice real-time SOC alerting and log correlation
- Gain exposure to ICS/SCADA threat modeling
- Study Active Directory attack paths in a safe environment

**KA:**
- გაიგეთ სრული kill chain დაზვერვიდან ზემოქმედებამდე
- ამოიცანით გავრცელებული შეტევის ტექნიკებით გენერირებული ფორენზიკული არტეფაქტები
- ივარჯიშეთ SOC-ის რეალურ დროში შეტყობინებებსა და ჟურნალების კორელაციაში
- გაეცანით ICS/SCADA საფრთხის მოდელირებას
- შეისწავლეთ Active Directory-ის შეტევის მარშრუტები უსაფრთხო გარემოში

---

## Disclaimer / პასუხისმგებლობის შეზღუდვა

**EN:** This project is intended strictly for educational and authorized security research purposes. All simulations run within a self-contained environment and do not interact with live systems or external networks. Unauthorized use of these techniques against real infrastructure is illegal and unethical. Always operate within the scope of a written authorization.

**KA:** ეს პროექტი განკუთვნილია მხოლოდ საგანმანათლებლო და ავტორიზებული უსაფრთხოების კვლევის მიზნებისთვის. ყველა სიმულაცია მუშაობს დახურულ გარემოში და არ ურთიერთქმედებს რეალურ სისტემებთან ან გარე ქსელებთან. ამ ტექნიკების გამოყენება რეალური ინფრასტრუქტურის წინააღმდეგ ავტორიზაციის გარეშე არის უკანონო და არაეთიკური. ყოველთვის იმოქმედეთ წერილობითი ავტორიზაციის ფარგლებში.

---

*CyberLab v3.0 — Built for defenders who think like attackers.*
