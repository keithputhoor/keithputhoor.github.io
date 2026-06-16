import React from 'react';

const projects = [
  {
    title: "Secure Enterprise Multi-Zone Network Architecture & IPsec VPN Lab",
    description: "Designed and implemented a secure multi-zone network architecture for 'CloudCafe' (a delivery-only cafe platform) spanning a Dubai HQ and an Abu Dhabi branch office, using Cisco Packet Tracer.",
    summary: [
      "VLAN Segmentation & Inter-VLAN Routing: Structured HQ into 8 security zones (Kitchen, IT, Admin, Delivery, Marketing, Customer Care, Web Server, Staff Wireless) and Abu Dhabi into 2 subnets.",
      "Access Control Lists (ACLs): Configured Extended ACL 100 on the main HQ router to restrict ICMP diagnostics exclusively to two authorized IT hosts (192.168.20.2/3) to prevent lateral reconnaissance. Configured ACL 102 on the Web Server (192.168.70.3) to restrict inbound access strictly to HTTPS (TCP port 443).",
      "Site-to-Site IPsec VPN: Established a secure tunnel between HQ (R1) and Abu Dhabi (R3) using AES encryption, SHA hashing, and Pre-Shared Key (vpnpa55) authentication to route delivery/logistics data securely over the public WAN.",
      "Zone-Based Policy Firewall (ZPF): Implemented ZPF on the HQ router defining IN-ZONE and OUT-ZONE, enforcing stateful packet inspection (IN-2-OUT-PMAP) to drop unauthorized incoming traffic.",
      "Enterprise Wireless Security: Deployed WPA2-Enterprise (802.1X) for staff using a central RADIUS server (192.168.200.3) on VLAN 200, alongside a completely isolated WPA2-Personal (PSK) customer guest Wi-Fi network."
    ],
    tags: ["Cisco IOS", "IPsec VPN", "Zone-Based Firewall (ZPF)", "VLAN Segmentation", "802.1X / RADIUS", "Extended ACLs"],
    repoLink: "https://github.com/keithputhoor/secure-enterprise-network",
    downloadLink: "/docs/network_architecture_report.docx",
    downloadLabel: "Download Report (DOCX)",
    sourceLink: "/docs/cloudcafe_network_topology.pkt",
    sourceLabel: "Download Packet Tracer (.pkt)"
  },
  {
    title: "Enterprise Vulnerability Assessment & Remediation Simulation",
    description: "Conducted a thorough vulnerability assessment of an enterprise network subnet (scope: 10.0.2.1 – 10.0.2.254) using Tenable Nessus Essentials, translating findings into a structured risk remediation plan.",
    summary: [
      "Vulnerability Detection: Configured and executed a Basic Network Scan, identifying critical database exposure and web application vulnerabilities.",
      "Critical Severity Mitigation: Identified an unprotected Redis Server (unauthenticated). Mitigation involved configuring password authentication via the requirepass directive in /etc/redis/redis.conf to prevent unauthorized database read/write/execution access.",
      "High Severity Mitigation: Detected an outdated Ruby Rack library (< 2.2.19) vulnerable to multipart request preamble DoS memory exhaustion. Remediated by upgrading Rack to patched versions (2.2.19/3.1.17/3.2.2+).",
      "Verification and Analysis: Executed follow-up scans to confirm successful patch deployment and security policy validation, drafting an executive report detailing CVSS v3 ratings and threat impacts."
    ],
    tags: ["Tenable Nessus", "Wireshark", "Vulnerability Management", "CVSS v3", "Port Scanning", "Remediation Planning"],
    repoLink: "https://github.com/keithputhoor/vulnerability-assessments",
    downloadLink: "/docs/nessus_assessment_report.pdf",
    downloadLabel: "Download Report (PDF)",
    sourceLink: null,
    sourceLabel: null
  },
  {
    title: "Heuristic & Machine Learning PDF Malware Scanner & Sanitizer",
    description: "Built a Python-based machine learning malware detection system and structural sanitization engine to analyze, classify, and wash malicious PDF documents without code execution.",
    summary: [
      "Static Analysis Engine: Developed a parser using the pypdf library to extract document structure (size, pages, trailers, xref tables) and count suspicious keywords (/JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFile, /XFA, /URI).",
      "Random Forest Classification: Trained an ensemble Random Forest model on the CIC_PDF_Malware_2022 dataset. RF was chosen for its interpretability (feature importance tracking) and performance on tabular metadata.",
      "Behavioral Sanitization: Engineered a reconstruction engine that programmatically creates a clean PDF, copying over only safe visual pages and surgically stripping out executable tags like /OpenAction and /XFA if the malware risk exceeds 50%.",
      "False Positive Resolution: Resolved a 66% risk false positive on a messy but benign SSRN academic paper. Obfuscation indicators (thousands of empty objects) were stripped by the sanitizer, producing a readable, safe document."
    ],
    tags: ["Python", "Scikit-Learn", "pypdf Parsing", "Random Forest", "Malware Analysis", "Behavioral Sanitization"],
    repoLink: "https://github.com/keithputhoor/pdf-malware-detector",
    downloadLink: "/docs/pdf_malware_ml_report.docx",
    downloadLabel: "Download Report (DOCX)",
    sourceLink: "/docs/pdf_malware_detector.py",
    sourceLabel: "Download Python Script (.py)"
  }
];

export default function ProjectShowcase() {
  return (
    <section className="mb-20" aria-labelledby="projects-heading">
      <h3 id="projects-heading" className="text-3xl font-bold text-slate-100 mb-8 border-b border-slate-800 pb-4 inline-block">
        Featured Engineering Projects
      </h3>
      <div className="flex flex-col gap-8">
        {projects.map((project, idx) => (
          <div 
            key={idx} 
            className="group relative bg-slate-900 border border-slate-800 rounded-2xl p-8 hover:border-cyan-500/50 hover:shadow-[0_0_30px_-5px_rgba(34,211,238,0.15)] transition-all duration-300 overflow-hidden"
          >
            {/* Subtle gradient background on hover */}
            <div className="absolute inset-0 bg-gradient-to-br from-cyan-950/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            
            <div className="relative z-10 flex flex-col xl:flex-row xl:justify-between gap-6">
              <div className="flex-1">
                <h4 className="text-2xl font-bold text-slate-200 group-hover:text-cyan-400 transition-colors mb-2">
                  {project.title}
                </h4>
                <p className="text-slate-400 text-sm mb-4 font-light italic">{project.description}</p>
                <ul className="space-y-2 mb-6 text-slate-300 leading-relaxed list-disc list-outside ml-5 text-sm">
                  {project.summary.map((point, pIdx) => (
                    <li key={pIdx}>{point}</li>
                  ))}
                </ul>
                <div className="flex flex-wrap gap-2 mb-6">
                  {project.tags.map((tag, tIdx) => (
                    <span key={tIdx} className="px-2.5 py-1 bg-slate-950/50 text-emerald-400/90 text-xs font-semibold rounded-md border border-emerald-900/30">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
              
              <div className="xl:w-64 flex flex-col gap-4 border-t xl:border-t-0 xl:border-l border-slate-800 pt-6 xl:pt-0 xl:pl-6 justify-between">
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800/80 shadow-inner">
                  <div className="flex items-center gap-2 text-amber-400/90 text-sm font-semibold mb-2">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    Available Deliverables
                  </div>
                  <ul className="text-xs text-slate-400 space-y-1.5 font-mono">
                    <li className="flex items-start gap-1.5">
                      <span className="text-cyan-500 mt-0.5">•</span> Raw Source/Config Files
                    </li>
                    <li className="flex items-start gap-1.5">
                      <span className="text-cyan-500 mt-0.5">•</span> PDF/DOCX Engineering Report
                    </li>
                  </ul>
                </div>
                
                <div className="flex flex-col gap-2">
                  <a 
                    href={project.downloadLink}
                    download
                    className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 hover:text-emerald-300 transition-colors text-sm font-medium"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                    {project.downloadLabel}
                  </a>

                  {project.sourceLink && (
                    <a 
                      href={project.sourceLink}
                      download
                      className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 hover:bg-indigo-500/20 hover:text-indigo-300 transition-colors text-sm font-medium"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                      {project.sourceLabel}
                    </a>
                  )}
                  
                  <a 
                    href={project.repoLink}
                    target="_blank"
                    rel="noopener noreferrer" 
                    className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg bg-cyan-950/30 text-cyan-400 border border-cyan-900/50 hover:bg-cyan-900/40 hover:text-cyan-300 transition-colors text-sm font-medium"
                  >
                    View Repository
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                  </a>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
