import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, Search, ChevronLeft, ChevronRight, Globe, Hash, Server } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

interface ThreatIndicator {
  indicator: string;
  type: string;
  threatSource: string;
  date: string;
  malwareAlias: string | null;
  confidence: number | null;
}

const PAGE_SIZE = 20;

async function fetchThreatIntel(): Promise<ThreatIndicator[]> {
  const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_iocs", days: 7 }),
  });
  if (!res.ok) throw new Error("Failed to fetch threat intel");
  const data = await res.json();

  if (data.query_status !== "ok" || !data.data) {
    return [];
  }

  return data.data.map((ioc: any) => ({
    indicator: ioc.ioc ?? "N/A",
    type: mapIocType(ioc.ioc_type ?? ""),
    threatSource: ioc.reporter ?? ioc.threat_type_desc ?? "ThreatFox",
    date: ioc.first_seen_utc?.split(" ")[0] ?? "N/A",
    malwareAlias: ioc.malware_printable ?? null,
    confidence: ioc.confidence_level ?? null,
  }));
}

function mapIocType(raw: string): string {
  const map: Record<string, string> = {
    ip_port: "IP Address",
    "ip:port": "IP Address",
    domain: "Domain",
    url: "Domain",
    md5_hash: "Malware Hash",
    sha256_hash: "Malware Hash",
    sha1_hash: "Malware Hash",
  };
  return map[raw.toLowerCase()] ?? (raw || "Unknown");
}

const typeIcon: Record<string, typeof Globe> = {
  "IP Address": Server,
  Domain: Globe,
  "Malware Hash": Hash,
};

const typeBadge: Record<string, string> = {
  "IP Address": "bg-destructive/20 text-destructive",
  Domain: "bg-[hsl(45,100%,50%)]/20 text-warning",
  "Malware Hash": "bg-secondary/20 text-secondary",
};

export default function ThreatIntel() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [page, setPage] = useState(0);

  const { data: allIndicators, isLoading, isError } = useQuery({
    queryKey: ["threat-intel-feed"],
    queryFn: fetchThreatIntel,
    staleTime: 5 * 60 * 1000,
  });

  const filtered = (allIndicators ?? []).filter((ind) => {
    if (typeFilter !== "all" && ind.type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        ind.indicator.toLowerCase().includes(q) ||
        ind.threatSource.toLowerCase().includes(q) ||
        (ind.malwareAlias?.toLowerCase().includes(q) ?? false)
      );
    }
    return true;
  });

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Reset page when filters change
  const handleFilterChange = (setter: (v: string) => void, val: string) => {
    setter(val);
    setPage(0);
  };

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
              <span className="font-mono text-xs text-muted-foreground">/ Threat Intel</span>
            </div>
            <div className="ml-auto flex items-center gap-1.5">
              <div className="h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
              <span className="font-mono text-xs text-muted-foreground hidden sm:inline">
                {allIndicators ? `${allIndicators.length} IOCs` : "Loading..."}
              </span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-4 cyber-grid overflow-auto">
            {/* Stats */}
            {allIndicators && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                  { label: "Malicious IPs", count: allIndicators.filter((i) => i.type === "IP Address").length, color: "text-destructive" },
                  { label: "Phishing Domains", count: allIndicators.filter((i) => i.type === "Domain").length, color: "text-warning" },
                  { label: "Malware Hashes", count: allIndicators.filter((i) => i.type === "Malware Hash").length, color: "text-secondary" },
                ].map((s) => (
                  <div key={s.label} className="bg-card border border-border rounded-lg p-4">
                    <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">{s.label}</p>
                    <p className={`font-mono text-3xl font-bold mt-1 ${s.color}`}>{s.count}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Filters */}
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search indicators, sources, malware..."
                    value={search}
                    onChange={(e) => handleFilterChange(setSearch, e.target.value)}
                    className="pl-9 font-mono text-sm bg-muted border-border"
                  />
                </div>
                <Select value={typeFilter} onValueChange={(v) => handleFilterChange(setTypeFilter, v)}>
                  <SelectTrigger className="w-[160px] font-mono text-xs bg-muted border-border">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="IP Address">IP Addresses</SelectItem>
                    <SelectItem value="Domain">Domains</SelectItem>
                    <SelectItem value="Malware Hash">Malware Hashes</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="font-mono text-xs text-muted-foreground mt-3">
                {filtered.length} indicators
                <span className="ml-2 text-primary">· powered by ThreatFox (abuse.ch)</span>
              </p>
            </div>

            {/* Table */}
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border">
                      {["Indicator", "Type", "Threat Source", "Malware", "Date"].map((h) => (
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
                    {isLoading &&
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i} className="border-b border-border/50">
                          {Array.from({ length: 5 }).map((_, j) => (
                            <td key={j} className="px-4 py-3">
                              <Skeleton className="h-4 w-full" />
                            </td>
                          ))}
                        </tr>
                      ))}
                    {isError && (
                      <tr>
                        <td colSpan={5} className="px-4 py-12 text-center font-mono text-sm text-destructive">
                          Failed to load threat intelligence data.
                        </td>
                      </tr>
                    )}
                    {!isLoading && !isError && paged.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-4 py-12 text-center font-mono text-sm text-muted-foreground">
                          No indicators match your filters.
                        </td>
                      </tr>
                    )}
                    {paged.map((ind, idx) => {
                      const Icon = typeIcon[ind.type] ?? Globe;
                      return (
                        <tr
                          key={`${ind.indicator}-${idx}`}
                          className="border-b border-border/50 hover:bg-muted/30 transition-colors"
                        >
                          <td className="px-4 py-3 font-mono text-sm text-foreground max-w-xs">
                            <div className="flex items-center gap-2">
                              <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                              <span className="truncate">{ind.indicator}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 whitespace-nowrap">
                            <span
                              className={`font-mono text-xs font-bold px-2 py-1 rounded-full ${
                                typeBadge[ind.type] ?? "bg-muted text-muted-foreground"
                              }`}
                            >
                              {ind.type}
                            </span>
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                            {ind.threatSource}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-secondary">
                            {ind.malwareAlias ?? "—"}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-muted-foreground whitespace-nowrap">
                            {ind.date}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between bg-card border border-border rounded-lg px-4 py-3">
                <p className="font-mono text-xs text-muted-foreground">
                  Page {page + 1} of {totalPages}
                </p>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    disabled={page === 0}
                    className="font-mono text-xs"
                  >
                    <ChevronLeft className="h-4 w-4 mr-1" />
                    Prev
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                    disabled={page >= totalPages - 1}
                    className="font-mono text-xs"
                  >
                    Next
                    <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                </div>
              </div>
            )}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
