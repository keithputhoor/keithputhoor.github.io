import React from 'react';

const skillsData = [
  {
    category: "Networking & Secure Infrastructure",
    skills: ["Cisco IOS", "Dynamic Routing (OSPF/RIPv2)", "VLAN Segmentation", "Inter-VLAN Routing", "Extended ACLs", "IPsec VPN (ESP/AH)", "Zone-Based Policy Firewalls (ZPF)"]
  },
  {
    category: "Security & Operations",
    skills: ["Tenable Nessus", "Metasploit Framework", "Wireshark", "Traffic & Protocol Analysis", "Vulnerability Management (CVSS v3)", "Cryptographic Email (SPF, DKIM, DMARC)", "PKI & TLS"]
  },
  {
    category: "Wireless Security",
    skills: ["WPA2-Enterprise (802.1X / RADIUS authentication)", "WPA2-Personal (PSK)"]
  },
  {
    category: "Machine Learning & Languages",
    skills: ["Python (Scikit-Learn, Pandas, NumPy)", "Random Forest Models", "Static Code & Metadata Analysis", "pypdf Parsing"]
  }
];

export default function SkillsMatrix() {
  return (
    <section className="mb-20" aria-labelledby="skills-heading">
      <h3 id="skills-heading" className="text-3xl font-bold text-slate-100 mb-8 border-b border-slate-800 pb-4 inline-block">
        Technical Capabilities
      </h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {skillsData.map((domain, idx) => (
          <div key={idx} className="bg-slate-900/50 rounded-xl p-6 border border-slate-800 hover:border-cyan-900/50 transition-colors">
            <h4 className="text-xl font-semibold text-emerald-400 mb-4">{domain.category}</h4>
            <div className="flex flex-wrap gap-2">
              {domain.skills.map((skill, sIdx) => (
                <span 
                  key={sIdx} 
                  className="px-3 py-1.5 bg-slate-950 text-slate-300 text-sm rounded-md border border-slate-800 shadow-sm"
                >
                  {skill}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
