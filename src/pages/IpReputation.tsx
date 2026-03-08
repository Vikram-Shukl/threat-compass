import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Shield, Search, ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle, Globe, Server } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { z } from "zod";
import { fetchThreatFox } from "@/lib/threatfoxApi";

const ipSchema = z
  .string()
  .trim()
  .regex(
    /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/,
    "Enter a valid IPv4 address"
  );

interface ReputationResult {
  ip: string;
  found: boolean;
  riskScore: number;
  classification: string;
  matches: {
    indicator: string;
    malware: string | null;
    threatType: string;
    confidence: number | null;
    firstSeen: string;
  }[];
}

async function checkIpReputation(ip: string): Promise<ReputationResult> {
  // Search ThreatFox for the IP
  const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "search_ioc", search_term: ip }),
  });
  if (!res.ok) throw new Error("Failed to query threat database");
  const data = await res.json();

  const iocs = data.data ?? [];
  const found = Array.isArray(iocs) && iocs.length > 0;

  if (!found) {
    return { ip, found: false, riskScore: 0, classification: "Clean", matches: [] };
  }

  const matches = iocs.map((ioc: any) => ({
    indicator: ioc.ioc ?? ip,
    malware: ioc.malware_printable ?? null,
    threatType: ioc.threat_type_desc ?? "Unknown",
    confidence: ioc.confidence_level ?? null,
    firstSeen: ioc.first_seen_utc?.split(" ")[0] ?? "N/A",
  }));

  // Calculate risk score based on confidence levels and match count
  const avgConfidence =
    matches.reduce((sum: number, m: any) => sum + (m.confidence ?? 50), 0) / matches.length;
  const riskScore = Math.min(100, Math.round(avgConfidence + Math.min(matches.length * 5, 20)));

  let classification = "Suspicious";
  if (riskScore >= 80) classification = "Malicious";
  else if (riskScore >= 50) classification = "Suspicious";
  else if (riskScore >= 20) classification = "Low Risk";

  return { ip, found, riskScore, classification, matches };
}

const classColors: Record<string, string> = {
  Clean: "text-primary",
  "Low Risk": "text-secondary",
  Suspicious: "text-warning",
  Malicious: "text-destructive",
};

const classIcons: Record<string, typeof Shield> = {
  Clean: ShieldCheck,
  "Low Risk": ShieldQuestion,
  Suspicious: AlertTriangle,
  Malicious: ShieldAlert,
};

const classBg: Record<string, string> = {
  Clean: "bg-primary/10 border-primary/30",
  "Low Risk": "bg-secondary/10 border-secondary/30",
  Suspicious: "bg-[hsl(45,100%,50%)]/10 border-[hsl(45,100%,50%)]/30",
  Malicious: "bg-destructive/10 border-destructive/30",
};

export default function IpReputation() {
  const [ipInput, setIpInput] = useState("");
  const [submittedIp, setSubmittedIp] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: result, isLoading, isError } = useQuery({
    queryKey: ["ip-reputation", submittedIp],
    queryFn: () => checkIpReputation(submittedIp!),
    enabled: !!submittedIp,
    staleTime: 2 * 60 * 1000,
  });

  const handleCheck = () => {
    const parsed = ipSchema.safeParse(ipInput);
    if (!parsed.success) {
      setValidationError(parsed.error.errors[0].message);
      return;
    }
    setValidationError(null);
    setSubmittedIp(parsed.data);
  };

  const ResultIcon = result ? classIcons[result.classification] : Shield;

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
              <span className="font-mono text-xs text-muted-foreground">/ IP Reputation</span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-6 cyber-grid overflow-auto">
            {/* Search */}
            <div className="bg-card border border-border rounded-lg p-6">
              <h2 className="font-mono text-lg font-bold text-foreground mb-1">IP Reputation Checker</h2>
              <p className="font-mono text-xs text-muted-foreground mb-4">
                Check if an IP address appears in known threat intelligence databases
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <Server className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Enter IP address (e.g. 192.168.1.1)"
                    value={ipInput}
                    onChange={(e) => {
                      setIpInput(e.target.value);
                      setValidationError(null);
                    }}
                    onKeyDown={(e) => e.key === "Enter" && handleCheck()}
                    className="pl-9 font-mono text-sm bg-muted border-border"
                    maxLength={15}
                  />
                </div>
                <Button onClick={handleCheck} disabled={isLoading} className="font-mono text-xs">
                  <Search className="h-4 w-4 mr-2" />
                  {isLoading ? "Checking..." : "Check Reputation"}
                </Button>
              </div>
              {validationError && (
                <p className="font-mono text-xs text-destructive mt-2">{validationError}</p>
              )}
            </div>

            {/* Results */}
            {isLoading && (
              <div className="bg-card border border-border rounded-lg p-8 text-center">
                <div className="inline-flex items-center gap-3">
                  <div className="h-5 w-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  <span className="font-mono text-sm text-muted-foreground">
                    Querying threat databases for {submittedIp}...
                  </span>
                </div>
              </div>
            )}

            {isError && (
              <div className="bg-card border border-destructive/50 rounded-lg p-6 text-center">
                <p className="font-mono text-sm text-destructive">
                  Failed to query threat database. Please try again.
                </p>
              </div>
            )}

            {result && !isLoading && (
              <>
                {/* Score Card */}
                <div className={`border rounded-lg p-6 ${classBg[result.classification]}`}>
                  <div className="flex flex-col sm:flex-row items-center gap-6">
                    {/* Risk Gauge */}
                    <div className="flex flex-col items-center">
                      <div className="relative h-28 w-28">
                        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
                          <circle
                            cx="50" cy="50" r="42"
                            fill="none"
                            stroke="hsl(220, 15%, 15%)"
                            strokeWidth="8"
                          />
                          <circle
                            cx="50" cy="50" r="42"
                            fill="none"
                            stroke={
                              result.riskScore >= 80 ? "hsl(0, 85%, 55%)"
                              : result.riskScore >= 50 ? "hsl(45, 100%, 50%)"
                              : result.riskScore >= 20 ? "hsl(190, 100%, 45%)"
                              : "hsl(160, 100%, 45%)"
                            }
                            strokeWidth="8"
                            strokeLinecap="round"
                            strokeDasharray={`${(result.riskScore / 100) * 264} 264`}
                          />
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <span className={`font-mono text-2xl font-bold ${classColors[result.classification]}`}>
                            {result.riskScore}
                          </span>
                          <span className="font-mono text-[10px] text-muted-foreground">/100</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex-1 text-center sm:text-left">
                      <div className="flex items-center gap-2 justify-center sm:justify-start mb-2">
                        <ResultIcon className={`h-5 w-5 ${classColors[result.classification]}`} />
                        <span className={`font-mono text-lg font-bold ${classColors[result.classification]}`}>
                          {result.classification}
                        </span>
                      </div>
                      <p className="font-mono text-sm text-foreground mb-1">
                        <Globe className="inline h-3.5 w-3.5 mr-1 text-muted-foreground" />
                        {result.ip}
                      </p>
                      <p className="font-mono text-xs text-muted-foreground">
                        {result.found
                          ? `Found in ${result.matches.length} threat record${result.matches.length > 1 ? "s" : ""}`
                          : "Not found in any known threat databases"}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Match Details */}
                {result.matches.length > 0 && (
                  <div className="bg-card border border-border rounded-lg overflow-hidden">
                    <div className="p-4 border-b border-border">
                      <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">
                        Threat Records
                      </h3>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-border">
                            {["Indicator", "Threat Type", "Malware", "Confidence", "First Seen"].map((h) => (
                              <th
                                key={h}
                                className="px-4 py-3 text-left font-mono text-xs text-muted-foreground uppercase tracking-wider"
                              >
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {result.matches.map((m, i) => (
                            <tr key={i} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                              <td className="px-4 py-3 font-mono text-sm text-secondary">{m.indicator}</td>
                              <td className="px-4 py-3 font-mono text-xs text-foreground">{m.threatType}</td>
                              <td className="px-4 py-3 font-mono text-xs text-warning">{m.malware ?? "—"}</td>
                              <td className="px-4 py-3 font-mono text-sm">
                                {m.confidence != null ? (
                                  <span className={m.confidence >= 75 ? "text-destructive" : m.confidence >= 50 ? "text-warning" : "text-muted-foreground"}>
                                    {m.confidence}%
                                  </span>
                                ) : "—"}
                              </td>
                              <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{m.firstSeen}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            )}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
