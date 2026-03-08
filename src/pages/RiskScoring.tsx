import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, Search, AlertTriangle, ShieldAlert, TrendingUp, Zap } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";

interface ScoredVulnerability {
  id: string;
  description: string;
  cvss: number | null;
  severity: string;
  published: string;
  exploitability: number;
  campaignRisk: number;
  riskScore: number;
  riskLevel: string;
  factors: string[];
}

// Known actively exploited CVE patterns and keywords
const ACTIVE_EXPLOIT_KEYWORDS = [
  "remote code execution", "rce", "arbitrary code", "buffer overflow",
  "sql injection", "command injection", "privilege escalation",
  "authentication bypass", "zero-day", "use-after-free",
];

const CAMPAIGN_KEYWORDS = [
  "actively exploited", "in the wild", "ransomware", "apt",
  "botnet", "worm", "trojan", "backdoor",
];

// High-profile products that attract threat campaigns
const HIGH_TARGET_PRODUCTS = [
  "apache", "nginx", "openssl", "linux kernel", "windows",
  "chrome", "firefox", "exchange", "log4j", "spring",
  "wordpress", "jenkins", "docker", "kubernetes", "tomcat",
  "php", "java", "python", "node.js", "weblogic",
];

function calculateRiskScore(cve: any): ScoredVulnerability {
  const desc =
    cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "";
  const metrics = cve.metrics ?? {};
  const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;
  const cvssData = cvss31 ?? cvss30 ?? cvss2;
  const score = cvssData?.baseScore ?? null;
  const severity = (
    cvss31?.baseSeverity ?? cvss30?.baseSeverity ??
    (score !== null ? (score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW") : "N/A")
  ).toUpperCase();

  const factors: string[] = [];
  const descLower = desc.toLowerCase();

  // 1. Base CVSS score contribution (0-40 points)
  const cvssComponent = score ? Math.round((score / 10) * 40) : 10;

  // 2. Exploitability assessment (0-30 points)
  let exploitability = 0;

  // Check attack vector
  const attackVector = cvssData?.attackVector ?? cvss31?.attackVector ?? "";
  if (attackVector === "NETWORK") { exploitability += 10; factors.push("Network-accessible"); }
  else if (attackVector === "ADJACENT_NETWORK") { exploitability += 5; }

  // Check complexity
  const complexity = cvssData?.attackComplexity ?? cvss31?.attackComplexity ?? "";
  if (complexity === "LOW") { exploitability += 8; factors.push("Low complexity"); }

  // Check for exploit indicators in description
  const hasExploitKeyword = ACTIVE_EXPLOIT_KEYWORDS.some((kw) => descLower.includes(kw));
  if (hasExploitKeyword) { exploitability += 12; factors.push("Exploit indicators found"); }

  // No user interaction required
  const userInteraction = cvssData?.userInteraction ?? "";
  if (userInteraction === "NONE") { exploitability += 5; factors.push("No user interaction needed"); }

  // No privileges required
  const privRequired = cvssData?.privilegesRequired ?? "";
  if (privRequired === "NONE") { exploitability += 5; factors.push("No privileges required"); }

  exploitability = Math.min(30, exploitability);

  // 3. Campaign risk assessment (0-30 points)
  let campaignRisk = 0;

  // Check for campaign-related keywords
  const hasCampaignKeyword = CAMPAIGN_KEYWORDS.some((kw) => descLower.includes(kw));
  if (hasCampaignKeyword) { campaignRisk += 15; factors.push("Active campaign indicators"); }

  // Check if targeting high-profile products
  const targetsHighProfile = HIGH_TARGET_PRODUCTS.some((p) => descLower.includes(p));
  if (targetsHighProfile) { campaignRisk += 10; factors.push("High-value target product"); }

  // Recency bonus (newer = higher campaign risk)
  const published = cve.published?.split("T")[0] ?? "";
  if (published) {
    const daysOld = Math.floor(
      (Date.now() - new Date(published).getTime()) / (1000 * 60 * 60 * 24)
    );
    if (daysOld <= 30) { campaignRisk += 10; factors.push("Published within 30 days"); }
    else if (daysOld <= 90) { campaignRisk += 5; factors.push("Published within 90 days"); }
  }

  // CISA KEV-style check (high CVSS + network + no auth)
  if (
    score && score >= 9 &&
    attackVector === "NETWORK" &&
    privRequired === "NONE"
  ) {
    campaignRisk += 5;
    factors.push("Critical network exposure");
  }

  campaignRisk = Math.min(30, campaignRisk);

  const riskScore = cvssComponent + exploitability + campaignRisk;
  const riskLevel =
    riskScore >= 80 ? "CRITICAL" :
    riskScore >= 60 ? "HIGH" :
    riskScore >= 40 ? "MEDIUM" : "LOW";

  return {
    id: cve.id,
    description: desc.length > 150 ? desc.slice(0, 150) + "…" : desc,
    cvss: score,
    severity,
    published,
    exploitability,
    campaignRisk,
    riskScore,
    riskLevel,
    factors,
  };
}

async function fetchAndScoreCves(keyword: string): Promise<ScoredVulnerability[]> {
  const params = new URLSearchParams({ resultsPerPage: "40" });
  if (keyword) params.set("keywordSearch", keyword);

  const res = await fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`
  );
  if (!res.ok) throw new Error("Failed to fetch CVEs");
  const data = await res.json();

  return data.vulnerabilities
    .map((v: any) => calculateRiskScore(v.cve))
    .sort((a: ScoredVulnerability, b: ScoredVulnerability) => b.riskScore - a.riskScore);
}

const riskColors: Record<string, string> = {
  CRITICAL: "text-destructive",
  HIGH: "text-warning",
  MEDIUM: "text-secondary",
  LOW: "text-primary",
};

const riskBadge: Record<string, string> = {
  CRITICAL: "bg-destructive/20 text-destructive",
  HIGH: "bg-[hsl(45,100%,50%)]/20 text-warning",
  MEDIUM: "bg-secondary/20 text-secondary",
  LOW: "bg-primary/20 text-primary",
};

const riskBarColor: Record<string, string> = {
  CRITICAL: "bg-destructive",
  HIGH: "bg-[hsl(45,100%,50%)]",
  MEDIUM: "bg-secondary",
  LOW: "bg-primary",
};

export default function RiskScoring() {
  const [search, setSearch] = useState("");
  const [submittedSearch, setSubmittedSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");

  const { data: scored, isLoading, isError } = useQuery({
    queryKey: ["risk-scoring", submittedSearch],
    queryFn: () => fetchAndScoreCves(submittedSearch),
    staleTime: 5 * 60 * 1000,
  });

  const filtered = (scored ?? []).filter((v) => {
    if (riskFilter !== "all" && v.riskLevel !== riskFilter) return false;
    return true;
  });

  const handleSearch = () => {
    setSubmittedSearch(search);
  };

  // Summary stats
  const stats = scored
    ? {
        critical: scored.filter((v) => v.riskLevel === "CRITICAL").length,
        high: scored.filter((v) => v.riskLevel === "HIGH").length,
        medium: scored.filter((v) => v.riskLevel === "MEDIUM").length,
        low: scored.filter((v) => v.riskLevel === "LOW").length,
        avgScore: Math.round(scored.reduce((s, v) => s + v.riskScore, 0) / (scored.length || 1)),
      }
    : null;

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
              <span className="font-mono text-xs text-muted-foreground">/ Risk Scoring</span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-4 cyber-grid overflow-auto">
            {/* Stats */}
            {stats && (
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <div className="bg-card border border-border rounded-lg p-4 text-center">
                  <TrendingUp className="h-4 w-4 text-muted-foreground mx-auto mb-1" />
                  <p className="font-mono text-2xl font-bold text-foreground">{stats.avgScore}</p>
                  <p className="font-mono text-[10px] text-muted-foreground uppercase">Avg Score</p>
                </div>
                {([
                  { label: "Critical", count: stats.critical, color: "text-destructive" },
                  { label: "High", count: stats.high, color: "text-warning" },
                  { label: "Medium", count: stats.medium, color: "text-secondary" },
                  { label: "Low", count: stats.low, color: "text-primary" },
                ] as const).map((s) => (
                  <div key={s.label} className="bg-card border border-border rounded-lg p-4 text-center">
                    <p className={`font-mono text-2xl font-bold ${s.color}`}>{s.count}</p>
                    <p className="font-mono text-[10px] text-muted-foreground uppercase">{s.label}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Search & Filters */}
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex flex-1 gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search CVEs by keyword (e.g. apache, log4j)..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                      className="pl-9 font-mono text-sm bg-muted border-border"
                    />
                  </div>
                  <button
                    onClick={handleSearch}
                    className="px-4 py-2 bg-primary text-primary-foreground font-mono text-xs rounded-md hover:bg-primary/90"
                  >
                    Analyze
                  </button>
                </div>
                <Select value={riskFilter} onValueChange={setRiskFilter}>
                  <SelectTrigger className="w-[140px] font-mono text-xs bg-muted border-border">
                    <SelectValue placeholder="Risk Level" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Levels</SelectItem>
                    <SelectItem value="CRITICAL">Critical</SelectItem>
                    <SelectItem value="HIGH">High</SelectItem>
                    <SelectItem value="MEDIUM">Medium</SelectItem>
                    <SelectItem value="LOW">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Scoring Methodology */}
            <div className="bg-card border border-border rounded-lg p-4">
              <h3 className="font-mono text-xs text-muted-foreground uppercase tracking-wider mb-3">Scoring Methodology</h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {[
                  { icon: ShieldAlert, label: "CVE Severity", desc: "CVSS base score (0–40 pts)", color: "text-destructive" },
                  { icon: Zap, label: "Exploit Availability", desc: "Attack vector, complexity, indicators (0–30 pts)", color: "text-warning" },
                  { icon: AlertTriangle, label: "Campaign Risk", desc: "Active threats, target value, recency (0–30 pts)", color: "text-secondary" },
                ].map((m) => (
                  <div key={m.label} className="flex items-start gap-3 p-3 bg-muted/30 rounded-md">
                    <m.icon className={`h-4 w-4 mt-0.5 shrink-0 ${m.color}`} />
                    <div>
                      <p className="font-mono text-xs font-bold text-foreground">{m.label}</p>
                      <p className="font-mono text-[10px] text-muted-foreground">{m.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Loading */}
            {isLoading && (
              <div className="space-y-2">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-24 w-full" />
                ))}
              </div>
            )}

            {isError && (
              <div className="bg-card border border-destructive/50 rounded-lg p-8 text-center">
                <p className="font-mono text-sm text-destructive">Failed to fetch and score vulnerabilities.</p>
              </div>
            )}

            {/* Scored Vulnerabilities */}
            {!isLoading && !isError && filtered.length === 0 && scored && (
              <p className="font-mono text-sm text-muted-foreground text-center py-8">
                No vulnerabilities match the selected risk level.
              </p>
            )}

            {filtered.map((vuln) => (
              <div
                key={vuln.id}
                className="bg-card border border-border rounded-lg p-4 hover:border-primary/30 transition-colors"
              >
                <div className="flex flex-col sm:flex-row gap-4">
                  {/* Risk Score Gauge */}
                  <div className="flex flex-col items-center justify-center w-20 shrink-0">
                    <div className="relative h-16 w-16">
                      <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                        <circle cx="50" cy="50" r="40" fill="none" stroke="hsl(220, 15%, 15%)" strokeWidth="8" />
                        <circle
                          cx="50" cy="50" r="40"
                          fill="none"
                          stroke={
                            vuln.riskScore >= 80 ? "hsl(0, 85%, 55%)"
                            : vuln.riskScore >= 60 ? "hsl(45, 100%, 50%)"
                            : vuln.riskScore >= 40 ? "hsl(190, 100%, 45%)"
                            : "hsl(160, 100%, 45%)"
                          }
                          strokeWidth="8"
                          strokeLinecap="round"
                          strokeDasharray={`${(vuln.riskScore / 100) * 251} 251`}
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className={`font-mono text-lg font-bold ${riskColors[vuln.riskLevel]}`}>
                          {vuln.riskScore}
                        </span>
                      </div>
                    </div>
                    <span className={`font-mono text-[10px] font-bold mt-1 ${riskColors[vuln.riskLevel]}`}>
                      {vuln.riskLevel}
                    </span>
                  </div>

                  {/* Details */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="font-mono text-sm font-bold text-secondary">{vuln.id}</span>
                      <span className={`font-mono text-[10px] px-2 py-0.5 rounded-full ${riskBadge[vuln.severity] ?? "bg-muted text-muted-foreground"}`}>
                        CVSS {vuln.cvss ?? "N/A"}
                      </span>
                      <span className="font-mono text-[10px] text-muted-foreground">{vuln.published}</span>
                    </div>
                    <p className="font-mono text-xs text-muted-foreground mb-3 line-clamp-2">{vuln.description}</p>

                    {/* Score Breakdown */}
                    <div className="grid grid-cols-3 gap-2 mb-2">
                      <div>
                        <p className="font-mono text-[10px] text-muted-foreground mb-0.5">Severity</p>
                        <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                          <div className="h-full bg-destructive rounded-full" style={{ width: `${((vuln.cvss ?? 0) / 10) * 100}%` }} />
                        </div>
                      </div>
                      <div>
                        <p className="font-mono text-[10px] text-muted-foreground mb-0.5">Exploitability</p>
                        <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                          <div className="h-full bg-[hsl(45,100%,50%)] rounded-full" style={{ width: `${(vuln.exploitability / 30) * 100}%` }} />
                        </div>
                      </div>
                      <div>
                        <p className="font-mono text-[10px] text-muted-foreground mb-0.5">Campaign Risk</p>
                        <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                          <div className="h-full bg-secondary rounded-full" style={{ width: `${(vuln.campaignRisk / 30) * 100}%` }} />
                        </div>
                      </div>
                    </div>

                    {/* Risk Factors */}
                    {vuln.factors.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {vuln.factors.map((f) => (
                          <span key={f} className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                            {f}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
