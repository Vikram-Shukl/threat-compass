import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, Search, ChevronRight, Layers } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
}

const TACTIC_ORDER = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
];

const TACTIC_IDS: Record<string, string> = {
  "TA0001": "Initial Access",
  "TA0002": "Execution",
  "TA0003": "Persistence",
  "TA0004": "Privilege Escalation",
  "TA0005": "Defense Evasion",
  "TA0006": "Credential Access",
};

const tacticColors: Record<string, string> = {
  "Initial Access": "border-l-destructive",
  Execution: "border-l-warning",
  Persistence: "border-l-secondary",
  "Privilege Escalation": "border-l-[hsl(280,100%,60%)]",
  "Defense Evasion": "border-l-[hsl(45,100%,50%)]",
  "Credential Access": "border-l-primary",
};

const tacticBadge: Record<string, string> = {
  "Initial Access": "bg-destructive/15 text-destructive",
  Execution: "bg-[hsl(45,100%,50%)]/15 text-warning",
  Persistence: "bg-secondary/15 text-secondary",
  "Privilege Escalation": "bg-[hsl(280,100%,60%)]/15 text-accent",
  "Defense Evasion": "bg-[hsl(45,100%,50%)]/15 text-warning",
  "Credential Access": "bg-primary/15 text-primary",
};

async function fetchMitreTechniques(): Promise<MitreTechnique[]> {
  const res = await fetch(
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
  );
  if (!res.ok) throw new Error("Failed to fetch MITRE data");
  const bundle = await res.json();

  const techniques: MitreTechnique[] = [];

  for (const obj of bundle.objects) {
    if (obj.type !== "attack-pattern" || obj.revoked || obj.x_mitre_deprecated) continue;

    const extRef = obj.external_references?.find(
      (r: any) => r.source_name === "mitre-attack"
    );
    if (!extRef?.external_id) continue;

    const killChainPhases = obj.kill_chain_phases ?? [];
    for (const phase of killChainPhases) {
      if (phase.kill_chain_name !== "mitre-attack") continue;

      // Map phase name to our tactic set
      const tacticName = phaseTacticMap(phase.phase_name);
      if (!tacticName) continue;

      techniques.push({
        id: extRef.external_id,
        name: obj.name,
        tactic: tacticName,
        description: (obj.description ?? "").slice(0, 200),
        url: extRef.url ?? `https://attack.mitre.org/techniques/${extRef.external_id.replace(".", "/")}/`,
      });
    }
  }

  // Sort by tactic order then ID
  techniques.sort((a, b) => {
    const ta = TACTIC_ORDER.indexOf(a.tactic);
    const tb = TACTIC_ORDER.indexOf(b.tactic);
    if (ta !== tb) return ta - tb;
    return a.id.localeCompare(b.id);
  });

  return techniques;
}

function phaseTacticMap(phase: string): string | null {
  const map: Record<string, string> = {
    "initial-access": "Initial Access",
    execution: "Execution",
    persistence: "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
  };
  return map[phase] ?? null;
}

export default function MitreExplorer() {
  const [search, setSearch] = useState("");
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

  const { data: techniques, isLoading, isError } = useQuery({
    queryKey: ["mitre-techniques"],
    queryFn: fetchMitreTechniques,
    staleTime: 12 * 60 * 60 * 1000,
    refetchInterval: 12 * 60 * 60 * 1000,
  });

  const grouped = useMemo(() => {
    if (!techniques) return {};
    const g: Record<string, MitreTechnique[]> = {};
    for (const t of techniques) {
      if (!g[t.tactic]) g[t.tactic] = [];
      g[t.tactic].push(t);
    }
    return g;
  }, [techniques]);

  const filtered = useMemo(() => {
    let items = techniques ?? [];
    if (selectedTactic) items = items.filter((t) => t.tactic === selectedTactic);
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (t) =>
          t.id.toLowerCase().includes(q) ||
          t.name.toLowerCase().includes(q) ||
          t.tactic.toLowerCase().includes(q)
      );
    }
    return items;
  }, [techniques, selectedTactic, search]);

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
              <span className="font-mono text-xs text-muted-foreground">/ MITRE ATT&CK Explorer</span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-4 cyber-grid overflow-auto">
            {/* Tactic Summary Cards */}
            {!isLoading && !isError && (
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {TACTIC_ORDER.map((tactic) => {
                  const count = grouped[tactic]?.length ?? 0;
                  const isActive = selectedTactic === tactic;
                  return (
                    <button
                      key={tactic}
                      onClick={() => setSelectedTactic(isActive ? null : tactic)}
                      className={`bg-card border rounded-lg p-3 text-left transition-all hover:scale-[1.02] ${
                        isActive
                          ? "border-primary glow-primary"
                          : "border-border hover:border-primary/40"
                      }`}
                    >
                      <p className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider leading-tight mb-1">
                        {tactic}
                      </p>
                      <p className="font-mono text-2xl font-bold text-foreground">{count}</p>
                      <p className="font-mono text-[10px] text-muted-foreground">techniques</p>
                    </button>
                  );
                })}
              </div>
            )}

            {/* Search */}
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex flex-col sm:flex-row gap-3 items-center">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search by technique ID, name, or tactic..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="pl-9 font-mono text-sm bg-muted border-border"
                  />
                </div>
                {selectedTactic && (
                  <button
                    onClick={() => setSelectedTactic(null)}
                    className="font-mono text-xs text-primary hover:underline whitespace-nowrap"
                  >
                    Clear filter: {selectedTactic} ×
                  </button>
                )}
                <span className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                  {filtered.length} techniques
                </span>
              </div>
            </div>

            {/* Loading */}
            {isLoading && (
              <div className="bg-card border border-border rounded-lg p-4 space-y-3">
                {Array.from({ length: 10 }).map((_, i) => (
                  <Skeleton key={i} className="h-14 w-full" />
                ))}
              </div>
            )}

            {isError && (
              <div className="bg-card border border-destructive/50 rounded-lg p-8 text-center">
                <p className="font-mono text-sm text-destructive">Failed to load MITRE ATT&CK data.</p>
              </div>
            )}

            {/* Techniques grouped by tactic */}
            {!isLoading && !isError && (
              <div className="space-y-4">
                {TACTIC_ORDER.filter(
                  (tactic) => !selectedTactic || selectedTactic === tactic
                ).map((tactic) => {
                  const tacticTechniques = (grouped[tactic] ?? []).filter((t) => {
                    if (!search) return true;
                    const q = search.toLowerCase();
                    return (
                      t.id.toLowerCase().includes(q) ||
                      t.name.toLowerCase().includes(q)
                    );
                  });
                  if (tacticTechniques.length === 0) return null;

                  return (
                    <div key={tactic} className="bg-card border border-border rounded-lg overflow-hidden">
                      <div className={`p-4 border-b border-border flex items-center gap-3 border-l-4 ${tacticColors[tactic]}`}>
                        <Layers className="h-4 w-4 text-muted-foreground" />
                        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">
                          {tactic}
                        </h3>
                        <span className={`font-mono text-xs px-2 py-0.5 rounded-full ${tacticBadge[tactic]}`}>
                          {tacticTechniques.length}
                        </span>
                      </div>
                      <div className="divide-y divide-border/50">
                        {tacticTechniques.map((tech) => (
                          <a
                            key={`${tech.id}-${tactic}`}
                            href={tech.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center px-4 py-3 hover:bg-muted/30 transition-colors group"
                          >
                            <span className="font-mono text-sm text-secondary font-bold w-24 shrink-0">
                              {tech.id}
                            </span>
                            <span className="font-mono text-sm text-foreground flex-1">
                              {tech.name}
                            </span>
                            <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                          </a>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
