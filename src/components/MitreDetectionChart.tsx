import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell,
} from "recharts";
import { Skeleton } from "@/components/ui/skeleton";
import { fetchThreatFox } from "@/lib/threatfoxApi";

interface TechniqueCount {
  name: string;
  id: string;
  count: number;
}

const BAR_COLORS = [
  "hsl(0, 85%, 55%)",
  "hsl(15, 90%, 55%)",
  "hsl(30, 95%, 52%)",
  "hsl(45, 100%, 50%)",
  "hsl(160, 100%, 45%)",
  "hsl(170, 90%, 42%)",
  "hsl(190, 100%, 45%)",
  "hsl(210, 80%, 55%)",
  "hsl(250, 70%, 60%)",
  "hsl(280, 100%, 60%)",
];

const tooltipStyle = {
  backgroundColor: "hsl(220, 18%, 10%)",
  border: "1px solid hsl(160, 30%, 18%)",
  borderRadius: "8px",
  fontFamily: "JetBrains Mono, monospace",
  fontSize: "12px",
};

async function fetchTopTechniques(): Promise<TechniqueCount[]> {
  const data = await fetchThreatFox({ query: "get_iocs", days: 7 });

  if (data.query_status !== "ok" || !data.data) return [];

  // Map ThreatFox tags to MITRE techniques
  const techniqueMap: Record<string, { id: string; name: string }> = {
    botnet: { id: "T1583", name: "Acquire Infrastructure" },
    "c2": { id: "T1071", name: "Application Layer Protocol" },
    "cc": { id: "T1071", name: "Application Layer Protocol" },
    stealer: { id: "T1555", name: "Credentials from Stores" },
    "info_stealer": { id: "T1555", name: "Credentials from Stores" },
    infostealer: { id: "T1555", name: "Credentials from Stores" },
    rat: { id: "T1219", name: "Remote Access Software" },
    ransomware: { id: "T1486", name: "Data Encrypted for Impact" },
    loader: { id: "T1105", name: "Ingress Tool Transfer" },
    dropper: { id: "T1105", name: "Ingress Tool Transfer" },
    downloader: { id: "T1105", name: "Ingress Tool Transfer" },
    miner: { id: "T1496", name: "Resource Hijacking" },
    cryptominer: { id: "T1496", name: "Resource Hijacking" },
    backdoor: { id: "T1059", name: "Command & Scripting Interpreter" },
    trojan: { id: "T1036", name: "Masquerading" },
    phishing: { id: "T1566", name: "Phishing" },
    exploit: { id: "T1203", name: "Exploitation for Client Execution" },
    keylogger: { id: "T1056", name: "Input Capture" },
    webshell: { id: "T1505", name: "Server Software Component" },
    spam: { id: "T1566", name: "Phishing" },
  };

  const counts: Record<string, TechniqueCount> = {};

  for (const ioc of data.data) {
    const tags: string[] = ioc.tags ?? [];
    const threatType = (ioc.threat_type ?? "").toLowerCase();
    const malware = (ioc.malware_printable ?? "").toLowerCase();

    // Check tags, threat type, and malware name
    const allTerms = [...tags.map((t: string) => t.toLowerCase()), threatType, malware];

    for (const term of allTerms) {
      for (const [key, tech] of Object.entries(techniqueMap)) {
        if (term.includes(key)) {
          if (!counts[tech.id]) {
            counts[tech.id] = { id: tech.id, name: tech.name, count: 0 };
          }
          counts[tech.id].count++;
          break;
        }
      }
    }
  }

  return Object.values(counts)
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
}

export function MitreDetectionChart() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["mitre-detection-chart"],
    queryFn: fetchTopTechniques,
    staleTime: 12 * 60 * 60 * 1000,
    refetchInterval: 12 * 60 * 60 * 1000,
  });

  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider mb-1">
        Top MITRE ATT&CK Techniques
      </h3>
      <p className="font-mono text-xs text-muted-foreground mb-4">
        Most common techniques detected in threat intelligence feeds (7 days)
      </p>

      {isLoading && <Skeleton className="h-[300px] w-full" />}

      {isError && (
        <p className="font-mono text-sm text-destructive text-center py-8">
          Failed to load detection data
        </p>
      )}

      {data && data.length === 0 && (
        <p className="font-mono text-sm text-muted-foreground text-center py-8">
          No technique detections in the last 7 days
        </p>
      )}

      {data && data.length > 0 && (
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(160, 30%, 18%)" horizontal={false} />
            <XAxis
              type="number"
              tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 11 }}
              allowDecimals={false}
            />
            <YAxis
              dataKey="name"
              type="category"
              tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 10 }}
              width={180}
            />
            <Tooltip
              contentStyle={tooltipStyle}
              formatter={(value: number) => [`${value} detections`, "Count"]}
              labelFormatter={(label: string) => {
                const item = data.find((d) => d.name === label);
                return item ? `${item.id} — ${item.name}` : label;
              }}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {data.map((_, i) => (
                <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
