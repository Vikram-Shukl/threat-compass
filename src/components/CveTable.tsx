import { useQuery } from "@tanstack/react-query";
import { Skeleton } from "@/components/ui/skeleton";

interface NvdCve {
  id: string;
  description: string;
  severity: string;
  cvss: number | null;
  published: string;
}

async function fetchCves(): Promise<NvdCve[]> {
  const res = await fetch(
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"
  );
  if (!res.ok) throw new Error("Failed to fetch CVEs");
  const data = await res.json();

  return data.vulnerabilities.map((v: any) => {
    const cve = v.cve;
    const desc =
      cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "N/A";

    // Try CVSS 3.1, then 3.0, then 2.0
    const metrics = cve.metrics ?? {};
    const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
    const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;
    const cvssData = cvss31 ?? cvss30 ?? cvss2;

    const score = cvssData?.baseScore ?? null;
    const severity = cvss31?.baseSeverity ?? cvss30?.baseSeverity ?? 
      (cvss2 ? (score! >= 7 ? "HIGH" : score! >= 4 ? "MEDIUM" : "LOW") : "N/A");

    return {
      id: cve.id,
      description: desc.length > 120 ? desc.slice(0, 120) + "…" : desc,
      severity: severity.toUpperCase(),
      cvss: score,
      published: cve.published?.split("T")[0] ?? "N/A",
    };
  });
}

const severityColor: Record<string, string> = {
  CRITICAL: "text-destructive",
  HIGH: "text-warning",
  MEDIUM: "text-secondary",
  LOW: "text-primary",
  "N/A": "text-muted-foreground",
};

export function CveTable() {
  const { data: cves, isLoading, isError } = useQuery({
    queryKey: ["nvd-cves"],
    queryFn: fetchCves,
    staleTime: 12 * 60 * 60 * 1000,
    refetchInterval: 12 * 60 * 60 * 1000,
  });

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="p-4 border-b border-border">
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">
          Latest CVEs
          <span className="text-xs text-muted-foreground ml-2 normal-case">via NVD API</span>
        </h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              {["CVE ID", "Description", "Severity", "CVSS", "Published"].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-mono text-xs text-muted-foreground uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading &&
              Array.from({ length: 5 }).map((_, i) => (
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
                <td colSpan={5} className="px-4 py-8 text-center font-mono text-sm text-destructive">
                  Failed to load CVEs from NVD
                </td>
              </tr>
            )}
            {cves?.map((cve) => (
              <tr key={cve.id} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                <td className="px-4 py-3 font-mono text-sm text-secondary whitespace-nowrap">{cve.id}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground max-w-xs">{cve.description}</td>
                <td className={`px-4 py-3 font-mono text-xs font-bold ${severityColor[cve.severity] ?? "text-muted-foreground"}`}>
                  {cve.severity}
                </td>
                <td className="px-4 py-3 font-mono text-sm">{cve.cvss ?? "—"}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground whitespace-nowrap">{cve.published}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
