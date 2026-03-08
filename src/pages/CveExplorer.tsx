import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, Search, ChevronLeft, ChevronRight } from "lucide-react";
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

interface NvdCveItem {
  id: string;
  description: string;
  severity: string;
  cvss: number | null;
  published: string;
}

const RESULTS_PER_PAGE = 20;

async function fetchCves({
  keyword,
  startIndex,
}: {
  keyword: string;
  startIndex: number;
}): Promise<{ cves: NvdCveItem[]; totalResults: number }> {
  const params = new URLSearchParams({
    resultsPerPage: String(RESULTS_PER_PAGE),
    startIndex: String(startIndex),
  });
  if (keyword) params.set("keywordSearch", keyword);

  const res = await fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`
  );
  if (!res.ok) throw new Error("Failed to fetch CVEs");
  const data = await res.json();

  const cves: NvdCveItem[] = data.vulnerabilities.map((v: any) => {
    const cve = v.cve;
    const desc =
      cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "N/A";
    const metrics = cve.metrics ?? {};
    const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
    const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;
    const cvssData = cvss31 ?? cvss30 ?? cvss2;
    const score = cvssData?.baseScore ?? null;

    let severity =
      cvss31?.baseSeverity ?? cvss30?.baseSeverity ?? null;
    if (!severity && score !== null) {
      severity =
        score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";
    }

    return {
      id: cve.id,
      description: desc,
      severity: severity?.toUpperCase() ?? "N/A",
      cvss: score,
      published: cve.published?.split("T")[0] ?? "N/A",
    };
  });

  return { cves, totalResults: data.totalResults ?? 0 };
}

const severityColor: Record<string, string> = {
  CRITICAL: "text-destructive",
  HIGH: "text-warning",
  MEDIUM: "text-secondary",
  LOW: "text-primary",
  "N/A": "text-muted-foreground",
};

const severityBadge: Record<string, string> = {
  CRITICAL: "bg-destructive/20 text-destructive",
  HIGH: "bg-[hsl(45,100%,50%)]/20 text-warning",
  MEDIUM: "bg-secondary/20 text-secondary",
  LOW: "bg-primary/20 text-primary",
  "N/A": "bg-muted text-muted-foreground",
};

const currentYear = new Date().getFullYear();
const years = Array.from({ length: 10 }, (_, i) => String(currentYear - i));

export default function CveExplorer() {
  const [search, setSearch] = useState("");
  const [submittedSearch, setSubmittedSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [year, setYear] = useState("all");
  const [page, setPage] = useState(0);

  const startIndex = page * RESULTS_PER_PAGE;

  const { data, isLoading, isError, isFetching } = useQuery({
    queryKey: ["cve-explorer", submittedSearch, startIndex],
    queryFn: () => fetchCves({ keyword: submittedSearch, startIndex }),
    staleTime: 12 * 60 * 60 * 1000,
    refetchInterval: 12 * 60 * 60 * 1000,
    placeholderData: (prev) => prev,
  });

  const handleSearch = () => {
    setPage(0);
    setSubmittedSearch(search);
  };

  // Client-side filters on fetched results
  const filtered = (data?.cves ?? []).filter((cve) => {
    if (severity !== "all" && cve.severity !== severity) return false;
    if (year !== "all" && !cve.published.startsWith(year)) return false;
    return true;
  });

  const totalResults = data?.totalResults ?? 0;
  const totalPages = Math.ceil(totalResults / RESULTS_PER_PAGE);

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <DashboardSidebar />
        <div className="flex-1 flex flex-col min-w-0">
          {/* Header */}
          <header className="h-12 flex items-center border-b border-border px-4 bg-card/50 backdrop-blur-sm sticky top-0 z-10">
            <SidebarTrigger className="mr-4" />
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              <span className="font-mono text-sm text-foreground font-semibold">SENTINEL</span>
              <span className="font-mono text-xs text-muted-foreground">/ CVE Explorer</span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-4 cyber-grid overflow-auto">
            {/* Filters */}
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1 flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search CVEs by keyword..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                      className="pl-9 font-mono text-sm bg-muted border-border"
                    />
                  </div>
                  <Button onClick={handleSearch} className="font-mono text-xs">
                    Search
                  </Button>
                </div>
                <Select value={severity} onValueChange={(v) => setSeverity(v)}>
                  <SelectTrigger className="w-[140px] font-mono text-xs bg-muted border-border">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    <SelectItem value="CRITICAL">Critical</SelectItem>
                    <SelectItem value="HIGH">High</SelectItem>
                    <SelectItem value="MEDIUM">Medium</SelectItem>
                    <SelectItem value="LOW">Low</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={year} onValueChange={(v) => setYear(v)}>
                  <SelectTrigger className="w-[120px] font-mono text-xs bg-muted border-border">
                    <SelectValue placeholder="Year" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Years</SelectItem>
                    {years.map((y) => (
                      <SelectItem key={y} value={y}>{y}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {totalResults > 0 && (
                <p className="font-mono text-xs text-muted-foreground mt-3">
                  {totalResults.toLocaleString()} results found
                  {isFetching && " • Loading..."}
                </p>
              )}
            </div>

            {/* Table */}
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border">
                      {["CVE ID", "Description", "Severity", "CVSS", "Published"].map((h) => (
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
                          Failed to load CVEs from NVD. Try again later.
                        </td>
                      </tr>
                    )}
                    {!isLoading && !isError && filtered.length === 0 && (
                      <tr>
                        <td colSpan={5} className="px-4 py-12 text-center font-mono text-sm text-muted-foreground">
                          No CVEs match your filters.
                        </td>
                      </tr>
                    )}
                    {filtered.map((cve) => (
                      <tr
                        key={cve.id}
                        className="border-b border-border/50 hover:bg-muted/30 transition-colors"
                      >
                        <td className="px-4 py-3 font-mono text-sm text-secondary whitespace-nowrap">
                          {cve.id}
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-muted-foreground max-w-md">
                          <span className="line-clamp-2">{cve.description}</span>
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap">
                          <span
                            className={`font-mono text-xs font-bold px-2 py-1 rounded-full ${
                              severityBadge[cve.severity] ?? severityBadge["N/A"]
                            }`}
                          >
                            {cve.severity}
                          </span>
                        </td>
                        <td className={`px-4 py-3 font-mono text-sm ${severityColor[cve.severity] ?? ""}`}>
                          {cve.cvss ?? "—"}
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-muted-foreground whitespace-nowrap">
                          {cve.published}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between bg-card border border-border rounded-lg px-4 py-3">
                <p className="font-mono text-xs text-muted-foreground">
                  Page {page + 1} of {totalPages.toLocaleString()}
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
