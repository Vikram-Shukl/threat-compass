const tactics = [
  { name: "Initial Access", techniques: 12, detected: 4, color: "bg-destructive/20 border-destructive/40" },
  { name: "Execution", techniques: 14, detected: 6, color: "bg-warning/20 border-warning/40" },
  { name: "Persistence", techniques: 19, detected: 3, color: "bg-secondary/20 border-secondary/40" },
  { name: "Privilege Escalation", techniques: 13, detected: 5, color: "bg-destructive/20 border-destructive/40" },
  { name: "Defense Evasion", techniques: 42, detected: 8, color: "bg-warning/20 border-warning/40" },
  { name: "Credential Access", techniques: 17, detected: 2, color: "bg-primary/20 border-primary/40" },
  { name: "Discovery", techniques: 31, detected: 7, color: "bg-secondary/20 border-secondary/40" },
  { name: "Lateral Movement", techniques: 9, detected: 1, color: "bg-primary/20 border-primary/40" },
  { name: "Collection", techniques: 17, detected: 3, color: "bg-secondary/20 border-secondary/40" },
  { name: "Exfiltration", techniques: 9, detected: 2, color: "bg-warning/20 border-warning/40" },
  { name: "Impact", techniques: 13, detected: 4, color: "bg-destructive/20 border-destructive/40" },
  { name: "Command & Control", techniques: 16, detected: 5, color: "bg-warning/20 border-warning/40" },
];

export function MitreGrid() {
  return (
    <div className="bg-card border border-border rounded-lg">
      <div className="p-4 border-b border-border">
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">MITRE ATT&CK Coverage</h3>
      </div>
      <div className="p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        {tactics.map(t => (
          <div key={t.name} className={`border rounded-md p-3 ${t.color} hover:scale-105 transition-transform cursor-pointer`}>
            <p className="font-mono text-xs font-semibold text-foreground mb-2 leading-tight">{t.name}</p>
            <div className="flex items-end justify-between">
              <div>
                <p className="font-mono text-lg font-bold text-foreground">{t.detected}</p>
                <p className="font-mono text-xs text-muted-foreground">detected</p>
              </div>
              <p className="font-mono text-xs text-muted-foreground">/{t.techniques}</p>
            </div>
            <div className="mt-2 h-1 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all"
                style={{ width: `${(t.detected / t.techniques) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
