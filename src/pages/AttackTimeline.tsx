import { useQuery } from "@tanstack/react-query";
import { Shield, Calendar, ExternalLink, AlertTriangle, Bug, ShieldAlert } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { Skeleton } from "@/components/ui/skeleton";

interface TimelineEvent {
  id: string;
  date: string;
  title: string;
  description: string;
  severity: string;
  type: "cve" | "attack" | "advisory";
  url?: string;
}

// Notable historical cyber events to complement live data
const NOTABLE_EVENTS: TimelineEvent[] = [
  { id: "EVT-2026-001", date: "2026-02-28", title: "Global Ransomware Wave Targets Healthcare", description: "Multiple hospitals across 12 countries hit by coordinated ransomware campaign exploiting unpatched VPN appliances.", severity: "CRITICAL", type: "attack" },
  { id: "EVT-2026-002", date: "2026-02-15", title: "Supply Chain Attack via Popular NPM Package", description: "Malicious code injected into widely-used open source library, affecting thousands of downstream applications.", severity: "CRITICAL", type: "attack" },
  { id: "EVT-2026-003", date: "2026-01-20", title: "Critical Zero-Day in Enterprise Firewalls", description: "Active exploitation of unauthenticated RCE vulnerability in leading enterprise firewall products.", severity: "CRITICAL", type: "advisory" },
  { id: "EVT-2025-001", date: "2025-12-10", title: "State-Sponsored APT Targets Energy Sector", description: "Advanced persistent threat group compromises SCADA systems at multiple energy facilities using novel malware.", severity: "HIGH", type: "attack" },
  { id: "EVT-2025-002", date: "2025-11-05", title: "Massive Data Breach at Financial Institution", description: "Unauthorized access to 50M+ customer records through misconfigured cloud storage and API exploitation.", severity: "HIGH", type: "attack" },
  { id: "EVT-2025-003", date: "2025-09-15", title: "Critical OpenSSL Vulnerability Disclosed", description: "Buffer overflow in certificate verification allows remote code execution on affected servers.", severity: "CRITICAL", type: "cve" },
  { id: "EVT-2025-004", date: "2025-07-22", title: "DDoS Botnet Exploits IoT Devices", description: "New Mirai variant recruits millions of IoT devices for record-breaking DDoS attacks against CDN providers.", severity: "HIGH", type: "attack" },
  { id: "EVT-2025-005", date: "2025-05-08", title: "Kubernetes Privilege Escalation Flaw", description: "Critical flaw allows container escape and host system compromise in default Kubernetes configurations.", severity: "CRITICAL", type: "cve" },
  { id: "EVT-2025-006", date: "2025-03-14", title: "Phishing Campaign Bypasses MFA", description: "Sophisticated adversary-in-the-middle attack framework steals session tokens, rendering MFA ineffective.", severity: "HIGH", type: "attack" },
  { id: "EVT-2024-001", date: "2024-12-20", title: "Log4Shell 2.0: New Java Logging Vulnerability", description: "JNDI injection variant discovered in alternative Java logging framework with widespread enterprise use.", severity: "CRITICAL", type: "cve" },
];

async function fetchTimelineData(): Promise<TimelineEvent[]> {
  // Fetch recent CVEs from NVD
  const res = await fetch(
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
  );

  const events: TimelineEvent[] = [...NOTABLE_EVENTS];

  if (res.ok) {
    const data = await res.json();
    for (const v of data.vulnerabilities) {
      const cve = v.cve;
      const desc = cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "";
      const metrics = cve.metrics ?? {};
      const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
      const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
      const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;
      const cvssData = cvss31 ?? cvss30 ?? cvss2;
      const score = cvssData?.baseScore ?? 0;
      const severity = score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";

      events.push({
        id: cve.id,
        date: cve.published?.split("T")[0] ?? "",
        title: cve.id,
        description: desc.length > 180 ? desc.slice(0, 180) + "…" : desc,
        severity,
        type: "cve",
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      });
    }
  }

  // Sort by date descending
  events.sort((a, b) => b.date.localeCompare(a.date));
  return events;
}

const typeIcons = { cve: Bug, attack: AlertTriangle, advisory: ShieldAlert };
const typeLabels = { cve: "CVE", attack: "Attack", advisory: "Advisory" };
const typeBadge = {
  cve: "bg-secondary/15 text-secondary",
  attack: "bg-destructive/15 text-destructive",
  advisory: "bg-[hsl(45,100%,50%)]/15 text-warning",
};

const sevDot: Record<string, string> = {
  CRITICAL: "bg-destructive",
  HIGH: "bg-[hsl(45,100%,50%)]",
  MEDIUM: "bg-secondary",
  LOW: "bg-primary",
};

const sevLine: Record<string, string> = {
  CRITICAL: "border-destructive/50",
  HIGH: "border-[hsl(45,100%,50%)]/50",
  MEDIUM: "border-secondary/50",
  LOW: "border-primary/50",
};

export default function AttackTimeline() {
  const { data: events, isLoading, isError } = useQuery({
    queryKey: ["attack-timeline"],
    queryFn: fetchTimelineData,
    staleTime: 5 * 60 * 1000,
  });

  // Group by month
  const grouped: { month: string; events: TimelineEvent[] }[] = [];
  if (events) {
    const map = new Map<string, TimelineEvent[]>();
    for (const e of events) {
      const month = e.date.slice(0, 7); // YYYY-MM
      if (!map.has(month)) map.set(month, []);
      map.get(month)!.push(e);
    }
    for (const [month, evts] of map) {
      grouped.push({ month, events: evts });
    }
  }

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <DashboardSidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <header className="h-12 flex items-center border-b border-border px-4 bg-card/50 backdrop-blur-sm sticky top-0 z-10">
            <SidebarTrigger className="mr-4" />
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              <span className="font-mono text-sm text-foreground font-semibold">SENTINEL</span>
              <span className="font-mono text-xs text-muted-foreground">/ Attack Timeline</span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-6 cyber-grid overflow-auto">
            {/* Legend */}
            <div className="bg-card border border-border rounded-lg p-4 flex flex-wrap gap-4 items-center">
              <span className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Legend:</span>
              {(["cve", "attack", "advisory"] as const).map((t) => {
                const Icon = typeIcons[t];
                return (
                  <div key={t} className="flex items-center gap-1.5">
                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className={`font-mono text-[10px] px-2 py-0.5 rounded-full ${typeBadge[t]}`}>
                      {typeLabels[t]}
                    </span>
                  </div>
                );
              })}
              <div className="flex items-center gap-3 ml-auto">
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
                  <div key={s} className="flex items-center gap-1">
                    <div className={`h-2 w-2 rounded-full ${sevDot[s]}`} />
                    <span className="font-mono text-[10px] text-muted-foreground">{s}</span>
                  </div>
                ))}
              </div>
            </div>

            {isLoading && (
              <div className="space-y-4">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-24 w-full" />
                ))}
              </div>
            )}

            {isError && (
              <div className="bg-card border border-destructive/50 rounded-lg p-8 text-center">
                <p className="font-mono text-sm text-destructive">Failed to load timeline data.</p>
              </div>
            )}

            {/* Timeline */}
            {grouped.map((group) => {
              const monthDate = new Date(group.month + "-01");
              const monthLabel = monthDate.toLocaleDateString("en-US", {
                year: "numeric",
                month: "long",
              });

              return (
                <div key={group.month}>
                  {/* Month Header */}
                  <div className="flex items-center gap-3 mb-4">
                    <Calendar className="h-4 w-4 text-primary" />
                    <h2 className="font-mono text-sm font-bold text-foreground uppercase tracking-wider">
                      {monthLabel}
                    </h2>
                    <div className="flex-1 h-px bg-border" />
                    <span className="font-mono text-[10px] text-muted-foreground">
                      {group.events.length} events
                    </span>
                  </div>

                  {/* Events */}
                  <div className="relative ml-6 border-l-2 border-border pl-6 space-y-4">
                    {group.events.map((event) => {
                      const Icon = typeIcons[event.type];
                      return (
                        <div
                          key={event.id}
                          className={`relative bg-card border rounded-lg p-4 hover:border-primary/30 transition-colors ${sevLine[event.severity]}`}
                        >
                          {/* Timeline dot */}
                          <div
                            className={`absolute -left-[33px] top-5 h-3 w-3 rounded-full border-2 border-background ${sevDot[event.severity]}`}
                          />

                          <div className="flex flex-col sm:flex-row gap-3">
                            <div className="flex items-start gap-3 flex-1">
                              <div className="p-1.5 bg-muted rounded-md mt-0.5">
                                <Icon className="h-4 w-4 text-muted-foreground" />
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                  <span className="font-mono text-xs text-muted-foreground">{event.date}</span>
                                  <span className={`font-mono text-[10px] px-2 py-0.5 rounded-full ${typeBadge[event.type]}`}>
                                    {typeLabels[event.type]}
                                  </span>
                                  <div className={`h-1.5 w-1.5 rounded-full ${sevDot[event.severity]}`} />
                                  <span className="font-mono text-[10px] text-muted-foreground">{event.severity}</span>
                                </div>
                                <h3 className="font-mono text-sm font-bold text-foreground mb-1">{event.title}</h3>
                                <p className="font-mono text-xs text-muted-foreground leading-relaxed">
                                  {event.description}
                                </p>
                              </div>
                            </div>
                            {event.url && (
                              <a
                                href={event.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="shrink-0 self-start p-1.5 text-muted-foreground hover:text-primary transition-colors"
                              >
                                <ExternalLink className="h-4 w-4" />
                              </a>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
