const cves = [
  { id: "CVE-2026-1234", severity: "CRITICAL", cvss: 9.8, product: "Apache Log4j", date: "2026-03-07", status: "Active" },
  { id: "CVE-2026-1190", severity: "HIGH", cvss: 8.1, product: "OpenSSL 3.x", date: "2026-03-06", status: "Patched" },
  { id: "CVE-2026-0987", severity: "CRITICAL", cvss: 9.1, product: "Linux Kernel", date: "2026-03-05", status: "Active" },
  { id: "CVE-2026-0876", severity: "MEDIUM", cvss: 6.5, product: "PostgreSQL", date: "2026-03-04", status: "Mitigated" },
  { id: "CVE-2026-0754", severity: "HIGH", cvss: 7.8, product: "Nginx", date: "2026-03-03", status: "Active" },
  { id: "CVE-2026-0621", severity: "LOW", cvss: 3.2, product: "Redis", date: "2026-03-02", status: "Patched" },
];

const severityColor: Record<string, string> = {
  CRITICAL: "text-destructive",
  HIGH: "text-warning",
  MEDIUM: "text-secondary",
  LOW: "text-primary",
};

const statusColor: Record<string, string> = {
  Active: "bg-destructive/20 text-destructive",
  Patched: "bg-primary/20 text-primary",
  Mitigated: "bg-secondary/20 text-secondary",
};

export function CveTable() {
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="p-4 border-b border-border">
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">Latest CVEs</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              {["CVE ID", "Severity", "CVSS", "Product", "Date", "Status"].map(h => (
                <th key={h} className="px-4 py-3 text-left font-mono text-xs text-muted-foreground uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cves.map(cve => (
              <tr key={cve.id} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                <td className="px-4 py-3 font-mono text-sm text-secondary">{cve.id}</td>
                <td className={`px-4 py-3 font-mono text-xs font-bold ${severityColor[cve.severity]}`}>{cve.severity}</td>
                <td className="px-4 py-3 font-mono text-sm">{cve.cvss}</td>
                <td className="px-4 py-3 font-mono text-sm text-foreground">{cve.product}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{cve.date}</td>
                <td className="px-4 py-3">
                  <span className={`font-mono text-xs px-2 py-1 rounded-full ${statusColor[cve.status]}`}>{cve.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
