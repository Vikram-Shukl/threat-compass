import { AlertTriangle, Globe, Lock, Zap } from "lucide-react";

const threats = [
  { icon: AlertTriangle, type: "Ransomware", title: "LockBit 4.0 variant targeting healthcare", time: "12m ago", severity: "critical" },
  { icon: Globe, type: "APT", title: "APT41 phishing campaign detected in APAC", time: "34m ago", severity: "high" },
  { icon: Lock, type: "Zero-Day", title: "Unpatched RCE in enterprise VPN appliance", time: "1h ago", severity: "critical" },
  { icon: Zap, type: "Malware", title: "New info-stealer spreading via npm packages", time: "2h ago", severity: "high" },
  { icon: Globe, type: "DDoS", title: "Volumetric attack on EU financial sector", time: "3h ago", severity: "medium" },
  { icon: AlertTriangle, type: "Supply Chain", title: "Compromised Docker image in public registry", time: "4h ago", severity: "high" },
];

const sevStyle: Record<string, string> = {
  critical: "border-l-destructive",
  high: "border-l-warning",
  medium: "border-l-secondary",
};

export function ThreatFeed() {
  return (
    <div className="bg-card border border-border rounded-lg">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">Threat Intel Feed</h3>
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
          <span className="font-mono text-xs text-muted-foreground">LIVE</span>
        </div>
      </div>
      <div className="divide-y divide-border/50">
        {threats.map((t, i) => (
          <div key={i} className={`p-4 border-l-2 ${sevStyle[t.severity]} hover:bg-muted/30 transition-colors cursor-pointer`}>
            <div className="flex items-start gap-3">
              <t.icon className="h-4 w-4 mt-0.5 text-muted-foreground shrink-0" />
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs text-secondary font-semibold">{t.type}</span>
                  <span className="font-mono text-xs text-muted-foreground">· {t.time}</span>
                </div>
                <p className="font-mono text-sm text-foreground truncate">{t.title}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
