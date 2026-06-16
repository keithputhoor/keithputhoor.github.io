import React from 'react';

export default function LabMetricsSidebar() {
  return (
    <aside className="bg-slate-900 border border-slate-800 rounded-2xl p-6 lg:sticky lg:top-8 w-full">
      <h3 className="text-xl font-bold text-slate-100 mb-6 border-b border-slate-800 pb-3 flex items-center gap-2">
        <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
        Hands-on Lab Practice
      </h3>
      
      <div className="space-y-6">
        {/* HackTheBox Metric */}
        <div>
          <div className="flex justify-between items-center mb-2">
            <span className="text-slate-300 font-medium flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse"></span>
              HackTheBox
            </span>
            <span className="text-emerald-400 text-sm font-medium">Active Platform</span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-2.5 border border-slate-800/80 overflow-hidden">
            <div className="bg-emerald-400 h-full rounded-full" style={{ width: '100%' }}></div>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono">Penetration Testing & Machine Exploits</p>
        </div>

        {/* TryHackMe Metric */}
        <div>
          <div className="flex justify-between items-center mb-2">
            <span className="text-slate-300 font-medium flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)] animate-pulse"></span>
              TryHackMe
            </span>
            <span className="text-cyan-400 text-sm font-medium">Active Platform</span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-2.5 border border-slate-800/80 overflow-hidden">
            <div className="bg-cyan-400 h-full rounded-full" style={{ width: '100%' }}></div>
          </div>
          <p className="text-xs text-slate-500 mt-2 font-mono">Guided Cybersecurity Labs & Scenarios</p>
        </div>

        {/* Continuous Training Focus */}
        <div className="pt-4 border-t border-slate-800">
          <p className="text-sm text-slate-400 mb-3 font-medium">Continuous Training Focus</p>
          <div className="flex flex-wrap gap-2">
            <span className="px-2.5 py-1 bg-slate-950 text-slate-400 text-xs rounded border border-slate-800">Offensive Security</span>
            <span className="px-2.5 py-1 bg-slate-950 text-slate-400 text-xs rounded border border-slate-800">Active Directory</span>
            <span className="px-2.5 py-1 bg-slate-950 text-slate-400 text-xs rounded border border-slate-800">Reverse Engineering</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
