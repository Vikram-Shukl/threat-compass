import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import { Skeleton } from "@/components/ui/skeleton";

interface SeverityCount {
  name: string;
  count: number;
  color: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "hsl(0, 85%, 55%)",
  HIGH: "hsl(45, 100%, 50%)",
  MEDIUM: "hsl(190, 100%, 45%)",
  LOW: "hsl(160, 100%, 45%)",
};

const tooltipStyle = {
  backgroundColor: "hsl(220, 18%, 10%)",
  border: "1px solid hsl(160, 30%, 18%)",
  borderRadius: "8px",
  fontFamily: "JetBrains Mono, monospace",
  fontSize: "12px",
};

async function fetchSeverityDistribution(): Promise<SeverityCount[]> {
  const res = await fetch(
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40"
  );
  if (!res.ok) throw new Error("Failed to fetch CVEs");
  const data = await res.json();

  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

  for (const v of data.vulnerabilities) {
    const metrics = v.cve.metrics ?? {};
    const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
    const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;
    const cvssData = cvss31 ?? cvss30 ?? cvss2;
    const score = cvssData?.baseScore ?? null;

    let severity = cvss31?.baseSeverity ?? cvss30?.baseSeverity ?? null;
    if (!severity && score !== null) {
      severity = score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";
    }
    if (severity) {
      const key = severity.toUpperCase();
      if (key in counts) counts[key]++;
    }
  }

  return Object.entries(counts).map(([name, count]) => ({
    name,
    count,
    color: SEVERITY_COLORS[name],
  }));
}

export function CveSeverityChart() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["nvd-severity-distribution"],
    queryFn: fetchSeverityDistribution,
    staleTime: 12 * 60 * 60 * 1000,
    refetchInterval: 12 * 60 * 60 * 1000,
  });

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
        CVE Severity Distribution
        <span className="text-xs text-muted-foreground ml-2 normal-case">live from NVD</span>
      </h3>

      {isLoading && (
        <div className="space-y-3">
          <Skeleton className="h-[280px] w-full" />
        </div>
      )}

      {isError && (
        <p className="font-mono text-sm text-destructive text-center py-8">
          Failed to load severity data
        </p>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Bar Chart */}
          <div>
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={data}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(160, 30%, 18%)" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 11 }}
                />
                <YAxis
                  tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 11 }}
                  allowDecimals={false}
                />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {data.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Donut Chart */}
          <div className="flex flex-col items-center">
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  dataKey="count"
                  paddingAngle={3}
                  nameKey="name"
                >
                  {data.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex gap-4 mt-2">
              {data.map((d) => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: d.color }} />
                  <span className="font-mono text-xs text-muted-foreground">
                    {d.name} ({d.count})
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
