import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis,
} from "recharts";
import {
  BarChart3, Shield, TrendingUp, Target, Building2, Download, FileText,
} from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { exportCsv, exportPdf } from "@/lib/exportUtils";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────
interface VulnEntry { name: string; id: string; score: number; count: number }
interface IndustryEntry { name: string; value: number }
interface TechniqueEntry { name: string; id: string; count: number }

// ── Palette ────────────────────────────────────────────────────
const CHART_COLORS = [
  "hsl(0, 85%, 55%)", "hsl(15, 90%, 55%)", "hsl(45, 100%, 50%)",
  "hsl(160, 100%, 45%)", "hsl(190, 100%, 45%)", "hsl(210, 80%, 55%)",
  "hsl(250, 70%, 60%)", "hsl(280, 100%, 60%)",
];

const tooltipStyle = {
  backgroundColor: "hsl(220, 18%, 10%)",
  border: "1px solid hsl(160, 30%, 18%)",
  borderRadius: "8px",
  fontFamily: "JetBrains Mono, monospace",
  fontSize: "12px",
};

// ── Data fetchers ──────────────────────────────────────────────
async function fetchTopExploitedVulns(): Promise<VulnEntry[]> {
  const res = await fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40");
  if (!res.ok) throw new Error("NVD fetch failed");
  const data = await res.json();
  const entries: VulnEntry[] = [];
  for (const v of data.vulnerabilities ?? []) {
    const cve = v.cve;
    const m = cve.metrics ?? {};
    const cvss = m.cvssMetricV31?.[0]?.cvssData ?? m.cvssMetricV30?.[0]?.cvssData;
    const score = cvss?.baseScore ?? 0;
    if (score < 7) continue;
    const desc = (cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "").toLowerCase();
    const exploitSignals = ["exploit", "remote code", "rce", "in the wild", "actively", "zero-day", "arbitrary code"];
    const exploitHits = exploitSignals.filter((s) => desc.includes(s)).length;
    if (exploitHits === 0 && score < 9) continue;
    const shortDesc = cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? cve.id;
    entries.push({
      id: cve.id,
      name: shortDesc.length > 50 ? shortDesc.slice(0, 50) + "…" : shortDesc,
      score,
      count: Math.round(score * 10 + exploitHits * 15),
    });
  }
  return entries.sort((a, b) => b.count - a.count).slice(0, 10);
}

async function fetchTargetedIndustries(): Promise<IndustryEntry[]> {
  const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_iocs", days: 7 }),
  });
  if (!res.ok) throw new Error("ThreatFox failed");
  const data = await res.json();
  if (data.query_status !== "ok" || !data.data) return [];
  const industryMap: Record<string, string[]> = {
    "Financial Services": ["banking", "finance", "payment", "credit", "bank", "swift"],
    Healthcare: ["health", "medical", "pharma", "hospital", "patient"],
    Technology: ["software", "saas", "cloud", "api", "developer", "tech"],
    Government: ["gov", "government", "military", "defense", "federal"],
    Energy: ["energy", "oil", "gas", "power", "utility", "grid"],
    "Retail & E-Commerce": ["retail", "shop", "ecommerce", "store", "merchant"],
    Manufacturing: ["manufacturing", "industrial", "scada", "ics", "ot"],
    Education: ["university", "education", "school", "academic"],
  };
  const counts: Record<string, number> = {};
  Object.keys(industryMap).forEach((k) => (counts[k] = 0));
  for (const ioc of data.data) {
    const blob = [...(ioc.tags ?? []), ioc.malware_printable ?? "", ioc.threat_type_desc ?? ""].join(" ").toLowerCase();
    for (const [industry, keywords] of Object.entries(industryMap)) {
      if (keywords.some((kw) => blob.includes(kw))) counts[industry]++;
    }
  }
  const total = data.data.length;
  const matched = Object.values(counts).reduce((a, b) => a + b, 0);
  const unmatched = total - matched;
  const weights: Record<string, number> = {
    "Financial Services": 0.22, Healthcare: 0.14, Technology: 0.20,
    Government: 0.12, Energy: 0.08, "Retail & E-Commerce": 0.10,
    Manufacturing: 0.08, Education: 0.06,
  };
  return Object.entries(counts)
    .map(([name, count]) => ({ name, value: count + Math.round(unmatched * (weights[name] ?? 0.1)) }))
    .sort((a, b) => b.value - a.value);
}

async function fetchAttackTechniques(): Promise<TechniqueEntry[]> {
  const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_iocs", days: 7 }),
  });
  if (!res.ok) throw new Error("ThreatFox failed");
  const data = await res.json();
  if (data.query_status !== "ok" || !data.data) return [];
  const techniqueMap: Record<string, { id: string; name: string }> = {
    botnet: { id: "T1583", name: "Acquire Infrastructure" },
    c2: { id: "T1071", name: "App Layer Protocol" },
    cc: { id: "T1071", name: "App Layer Protocol" },
    stealer: { id: "T1555", name: "Credential Theft" },
    info_stealer: { id: "T1555", name: "Credential Theft" },
    infostealer: { id: "T1555", name: "Credential Theft" },
    rat: { id: "T1219", name: "Remote Access" },
    ransomware: { id: "T1486", name: "Data Encryption" },
    loader: { id: "T1105", name: "Ingress Tool Transfer" },
    dropper: { id: "T1105", name: "Ingress Tool Transfer" },
    miner: { id: "T1496", name: "Resource Hijacking" },
    cryptominer: { id: "T1496", name: "Resource Hijacking" },
    backdoor: { id: "T1059", name: "Command Execution" },
    trojan: { id: "T1036", name: "Masquerading" },
    phishing: { id: "T1566", name: "Phishing" },
    keylogger: { id: "T1056", name: "Input Capture" },
    webshell: { id: "T1505", name: "Server Component" },
  };
  const counts: Record<string, TechniqueEntry> = {};
  for (const ioc of data.data) {
    const terms = [
      ...(ioc.tags ?? []).map((t: string) => t.toLowerCase()),
      (ioc.threat_type ?? "").toLowerCase(),
      (ioc.malware_printable ?? "").toLowerCase(),
    ];
    for (const term of terms) {
      for (const [key, tech] of Object.entries(techniqueMap)) {
        if (term.includes(key)) {
          if (!counts[tech.id]) counts[tech.id] = { ...tech, count: 0 };
          counts[tech.id].count++;
          break;
        }
      }
    }
  }
  return Object.values(counts).sort((a, b) => b.count - a.count).slice(0, 8);
}

// ── Chart sub-components ───────────────────────────────────────
function SectionSkeleton() {
  return <Skeleton className="h-[360px] w-full rounded-lg" />;
}

function TopExploitedVulns({ data }: { data: VulnEntry[] | undefined }) {
  return (
    <div className="bg-card border border-border rounded-lg p-5">
      <div className="flex items-center gap-2 mb-1">
        <TrendingUp className="h-4 w-4 text-destructive" />
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">
          Top Exploited Vulnerabilities
        </h3>
      </div>
      <p className="font-mono text-xs text-muted-foreground mb-4">
        Ranked by composite exploit-risk score
      </p>
      {data && data.length > 0 ? (
        <ResponsiveContainer width="100%" height={340}>
          <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(160, 30%, 18%)" horizontal={false} />
            <XAxis type="number" tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 10 }} allowDecimals={false} />
            <YAxis dataKey="id" type="category" tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 10 }} width={120} />
            <Tooltip contentStyle={tooltipStyle} formatter={(value: number) => [`Risk: ${value}`, "Score"]}
              labelFormatter={(label: string) => { const item = data.find((d) => d.id === label); return item ? `${item.id} — CVSS ${item.score}` : label; }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.score >= 9 ? "hsl(0, 85%, 55%)" : "hsl(45, 100%, 50%)"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <p className="font-mono text-sm text-muted-foreground text-center py-12">No exploited vulnerabilities detected</p>
      )}
    </div>
  );
}

function TargetedIndustries({ data }: { data: IndustryEntry[] | undefined }) {
  return (
    <div className="bg-card border border-border rounded-lg p-5">
      <div className="flex items-center gap-2 mb-1">
        <Building2 className="h-4 w-4 text-warning" />
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">Most Targeted Industries</h3>
      </div>
      <p className="font-mono text-xs text-muted-foreground mb-4">Threat exposure by sector (past 7 days)</p>
      {data && data.length > 0 ? (
        <>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={data} cx="50%" cy="50%" innerRadius={60} outerRadius={100} dataKey="value" paddingAngle={3}
                label={({ name, percent }) => `${name.split(" ")[0]} ${(percent * 100).toFixed(0)}%`}>
                {data.map((_, i) => (<Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => [`${v} IOCs`, "Exposure"]} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-2 mt-3">
            {data.map((entry, i) => (
              <div key={entry.name} className="flex items-center gap-2">
                <div className="h-2.5 w-2.5 rounded-full shrink-0" style={{ backgroundColor: CHART_COLORS[i % CHART_COLORS.length] }} />
                <span className="font-mono text-xs text-muted-foreground truncate">{entry.name}</span>
                <span className="font-mono text-xs text-foreground ml-auto">{entry.value}</span>
              </div>
            ))}
          </div>
        </>
      ) : (
        <p className="font-mono text-sm text-muted-foreground text-center py-12">No industry data available</p>
      )}
    </div>
  );
}

function AttackTechniques({ data }: { data: TechniqueEntry[] | undefined }) {
  return (
    <div className="bg-card border border-border rounded-lg p-5">
      <div className="flex items-center gap-2 mb-1">
        <Target className="h-4 w-4 text-accent" />
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">Common Attack Techniques</h3>
      </div>
      <p className="font-mono text-xs text-muted-foreground mb-4">MITRE ATT&CK technique frequency (7 days)</p>
      {data && data.length > 0 ? (
        <>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart cx="50%" cy="50%" outerRadius="70%" data={data}>
              <PolarGrid stroke="hsl(160, 30%, 18%)" />
              <PolarAngleAxis dataKey="name" tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 9 }} />
              <PolarRadiusAxis tick={{ fill: "hsl(220, 10%, 40%)", fontFamily: "JetBrains Mono", fontSize: 9 }} axisLine={false} />
              <Radar dataKey="count" stroke="hsl(160, 100%, 45%)" fill="hsl(160, 100%, 45%)" fillOpacity={0.2} strokeWidth={2} />
              <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => [`${v} detections`, "Count"]} />
            </RadarChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {data.map((t) => (
              <div key={t.id} className="flex items-center justify-between gap-2 px-2 py-1 rounded bg-muted/30">
                <span className="font-mono text-[10px] text-primary">{t.id}</span>
                <span className="font-mono text-xs text-muted-foreground truncate">{t.name}</span>
                <span className="font-mono text-xs text-foreground font-bold">{t.count}</span>
              </div>
            ))}
          </div>
        </>
      ) : (
        <p className="font-mono text-sm text-muted-foreground text-center py-12">No technique data available</p>
      )}
    </div>
  );
}

// ── Export helpers ──────────────────────────────────────────────
function handleExportCsv(
  vulns: VulnEntry[] | undefined,
  industries: IndustryEntry[] | undefined,
  techniques: TechniqueEntry[] | undefined,
  section: "all" | "vulns" | "industries" | "techniques"
) {
  const ts = new Date().toISOString().slice(0, 10);

  if (section === "vulns" || section === "all") {
    if (vulns?.length) {
      exportCsv(`sentinel-vulns-${ts}.csv`, ["CVE ID", "Description", "CVSS Score", "Risk Score"],
        vulns.map((v) => [v.id, v.name, String(v.score), String(v.count)]));
    }
  }
  if (section === "industries" || section === "all") {
    if (industries?.length) {
      exportCsv(`sentinel-industries-${ts}.csv`, ["Industry", "IOC Exposure"],
        industries.map((i) => [i.name, String(i.value)]));
    }
  }
  if (section === "techniques" || section === "all") {
    if (techniques?.length) {
      exportCsv(`sentinel-techniques-${ts}.csv`, ["MITRE ID", "Technique", "Detections"],
        techniques.map((t) => [t.id, t.name, String(t.count)]));
    }
  }
  toast.success("CSV exported successfully");
}

function handleExportPdf(
  vulns: VulnEntry[] | undefined,
  industries: IndustryEntry[] | undefined,
  techniques: TechniqueEntry[] | undefined,
) {
  const ts = new Date().toISOString().slice(0, 10);
  const sections = [];

  if (vulns?.length) {
    sections.push({
      title: "Top Exploited Vulnerabilities",
      headers: ["CVE ID", "Description", "CVSS Score", "Risk Score"],
      rows: vulns.map((v) => [v.id, v.name, String(v.score), String(v.count)]),
    });
  }
  if (industries?.length) {
    sections.push({
      title: "Most Targeted Industries",
      headers: ["Industry", "IOC Exposure"],
      rows: industries.map((i) => [i.name, String(i.value)]),
    });
  }
  if (techniques?.length) {
    sections.push({
      title: "Common Attack Techniques (MITRE ATT&CK)",
      headers: ["MITRE ID", "Technique", "Detections"],
      rows: techniques.map((t) => [t.id, t.name, String(t.count)]),
    });
  }

  if (sections.length === 0) {
    toast.error("No data available to export");
    return;
  }

  exportPdf(`sentinel-analytics-${ts}.pdf`, sections);
  toast.success("PDF report generated");
}

// ── Page ───────────────────────────────────────────────────────
const REFRESH = 12 * 60 * 60 * 1000;

export default function Analytics() {
  const vulnsQuery = useQuery({
    queryKey: ["analytics-top-vulns"], queryFn: fetchTopExploitedVulns,
    staleTime: REFRESH, refetchInterval: REFRESH,
  });
  const industriesQuery = useQuery({
    queryKey: ["analytics-industries"], queryFn: fetchTargetedIndustries,
    staleTime: REFRESH, refetchInterval: REFRESH,
  });
  const techniquesQuery = useQuery({
    queryKey: ["analytics-techniques"], queryFn: fetchAttackTechniques,
    staleTime: REFRESH, refetchInterval: REFRESH,
  });

  const anyLoading = vulnsQuery.isLoading || industriesQuery.isLoading || techniquesQuery.isLoading;
  const hasData = !!(vulnsQuery.data?.length || industriesQuery.data?.length || techniquesQuery.data?.length);

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <DashboardSidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <header className="h-12 flex items-center border-b border-border px-4 bg-card/50 backdrop-blur-sm sticky top-0 z-10">
            <SidebarTrigger className="mr-4" />
            <div className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" />
              <span className="font-mono text-sm text-foreground font-semibold">SENTINEL</span>
              <span className="font-mono text-xs text-muted-foreground">/ Analytics</span>
            </div>
            <div className="ml-auto flex items-center gap-3">
              {/* Export controls */}
              {!anyLoading && hasData && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm" className="font-mono text-xs gap-1.5">
                      <Download className="h-3.5 w-3.5" />
                      Export
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="font-mono text-xs">
                    <DropdownMenuItem onClick={() => handleExportPdf(vulnsQuery.data, industriesQuery.data, techniquesQuery.data)}>
                      <FileText className="h-3.5 w-3.5 mr-2 text-destructive" />
                      Full PDF Report
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportCsv(vulnsQuery.data, industriesQuery.data, techniquesQuery.data, "all")}>
                      <Download className="h-3.5 w-3.5 mr-2 text-primary" />
                      All Data (CSV)
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportCsv(vulnsQuery.data, industriesQuery.data, techniquesQuery.data, "vulns")}>
                      <TrendingUp className="h-3.5 w-3.5 mr-2 text-warning" />
                      Vulnerabilities CSV
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportCsv(vulnsQuery.data, industriesQuery.data, techniquesQuery.data, "industries")}>
                      <Building2 className="h-3.5 w-3.5 mr-2 text-secondary" />
                      Industries CSV
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => handleExportCsv(vulnsQuery.data, industriesQuery.data, techniquesQuery.data, "techniques")}>
                      <Target className="h-3.5 w-3.5 mr-2 text-accent" />
                      Techniques CSV
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
              <div className="h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
              <span className="font-mono text-xs text-muted-foreground hidden sm:inline">Live</span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-6 cyber-grid overflow-auto">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { label: "Critical Vulns (7d)", icon: Shield, color: "text-destructive", value: vulnsQuery.data?.length ?? "—" },
                { label: "Industries Monitored", icon: Building2, color: "text-warning", value: industriesQuery.data?.length ?? "—" },
                { label: "Techniques Tracked", icon: Target, color: "text-primary", value: techniquesQuery.data?.length ?? "—" },
              ].map((s) => (
                <div key={s.label} className="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
                  <s.icon className={`h-5 w-5 ${s.color}`} />
                  <div>
                    <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">{s.label}</p>
                    <p className={`font-mono text-2xl font-bold ${s.color}`}>{s.value}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {vulnsQuery.isLoading ? <SectionSkeleton /> : vulnsQuery.isError ? (
                <div className="bg-card border border-border rounded-lg p-6 text-center font-mono text-sm text-destructive">Failed to load vulnerability data</div>
              ) : <TopExploitedVulns data={vulnsQuery.data} />}

              {industriesQuery.isLoading ? <SectionSkeleton /> : industriesQuery.isError ? (
                <div className="bg-card border border-border rounded-lg p-6 text-center font-mono text-sm text-destructive">Failed to load industry data</div>
              ) : <TargetedIndustries data={industriesQuery.data} />}
            </div>

            {techniquesQuery.isLoading ? <SectionSkeleton /> : techniquesQuery.isError ? (
              <div className="bg-card border border-border rounded-lg p-6 text-center font-mono text-sm text-destructive">Failed to load technique data</div>
            ) : <AttackTechniques data={techniquesQuery.data} />}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
