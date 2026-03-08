import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Shield, Search, Users, Bug, Target, Building2, ChevronDown, ChevronUp } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";

interface ThreatActor {
  name: string;
  aliases: string[];
  description: string;
  malware: string[];
  techniques: { id: string; name: string }[];
  industries: string[];
  url: string;
}

async function fetchThreatActors(): Promise<ThreatActor[]> {
  const res = await fetch(
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
  );
  if (!res.ok) throw new Error("Failed to fetch MITRE data");
  const bundle = await res.json();

  const objects = bundle.objects;

  // Build lookup maps
  const idToObj: Record<string, any> = {};
  for (const obj of objects) {
    if (obj.id) idToObj[obj.id] = obj;
  }

  // Get relationships
  const groupUsesRelationships = objects.filter(
    (o: any) =>
      o.type === "relationship" &&
      o.relationship_type === "uses" &&
      o.source_ref?.startsWith("intrusion-set--")
  );

  // Get groups
  const groups = objects.filter(
    (o: any) => o.type === "intrusion-set" && !o.revoked && !o.x_mitre_deprecated
  );

  return groups.map((group: any) => {
    const extRef = group.external_references?.find(
      (r: any) => r.source_name === "mitre-attack"
    );

    const aliases = (group.aliases ?? []).filter((a: string) => a !== group.name);

    // Find related malware and techniques
    const rels = groupUsesRelationships.filter(
      (r: any) => r.source_ref === group.id
    );

    const malwareSet = new Set<string>();
    const techniques: { id: string; name: string }[] = [];
    const techniqueIds = new Set<string>();

    for (const rel of rels) {
      const target = idToObj[rel.target_ref];
      if (!target || target.revoked) continue;

      if (target.type === "malware" || target.type === "tool") {
        malwareSet.add(target.name);
      } else if (target.type === "attack-pattern") {
        const techRef = target.external_references?.find(
          (r: any) => r.source_name === "mitre-attack"
        );
        if (techRef?.external_id && !techniqueIds.has(techRef.external_id)) {
          techniqueIds.add(techRef.external_id);
          techniques.push({ id: techRef.external_id, name: target.name });
        }
      }
    }

    // Extract targeted industries from description
    const industries = extractIndustries(group.description ?? "");

    return {
      name: group.name,
      aliases,
      description: (group.description ?? "").replace(/\(Citation:[^)]*\)/g, "").trim(),
      malware: Array.from(malwareSet).sort(),
      techniques: techniques.sort((a, b) => a.id.localeCompare(b.id)),
      industries,
      url: extRef?.url ?? "",
    };
  }).sort((a: ThreatActor, b: ThreatActor) => a.name.localeCompare(b.name));
}

function extractIndustries(desc: string): string[] {
  const industryKeywords: Record<string, string> = {
    government: "Government",
    military: "Military",
    defense: "Defense",
    financial: "Financial",
    banking: "Financial",
    healthcare: "Healthcare",
    energy: "Energy",
    telecommunications: "Telecommunications",
    telecom: "Telecommunications",
    technology: "Technology",
    aerospace: "Aerospace",
    education: "Education",
    media: "Media",
    retail: "Retail",
    manufacturing: "Manufacturing",
    "critical infrastructure": "Critical Infrastructure",
    transportation: "Transportation",
    oil: "Energy",
    pharmaceutical: "Healthcare",
    automotive: "Automotive",
    hospitality: "Hospitality",
  };

  const found = new Set<string>();
  const lower = desc.toLowerCase();
  for (const [keyword, label] of Object.entries(industryKeywords)) {
    if (lower.includes(keyword)) found.add(label);
  }
  return Array.from(found).sort();
}

function ActorCard({ actor }: { actor: ThreatActor }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/30 transition-colors">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 flex items-start gap-4"
      >
        <div className="p-2 bg-destructive/10 rounded-md mt-0.5">
          <Users className="h-5 w-5 text-destructive" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-mono text-sm font-bold text-foreground">{actor.name}</h3>
            {actor.aliases.length > 0 && (
              <span className="font-mono text-[10px] text-muted-foreground">
                aka {actor.aliases.slice(0, 3).join(", ")}
                {actor.aliases.length > 3 && ` +${actor.aliases.length - 3}`}
              </span>
            )}
          </div>
          <div className="flex gap-4 mt-1.5">
            <span className="font-mono text-[10px] text-secondary flex items-center gap-1">
              <Bug className="h-3 w-3" /> {actor.malware.length} malware
            </span>
            <span className="font-mono text-[10px] text-warning flex items-center gap-1">
              <Target className="h-3 w-3" /> {actor.techniques.length} techniques
            </span>
            <span className="font-mono text-[10px] text-primary flex items-center gap-1">
              <Building2 className="h-3 w-3" /> {actor.industries.length} industries
            </span>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-muted-foreground shrink-0 mt-1" />
        ) : (
          <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0 mt-1" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-border/50 pt-4">
          {/* Description */}
          <p className="font-mono text-xs text-muted-foreground leading-relaxed line-clamp-4">
            {actor.description.slice(0, 400)}
            {actor.description.length > 400 && "…"}
          </p>

          {/* Malware */}
          {actor.malware.length > 0 && (
            <div>
              <h4 className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Bug className="h-3 w-3" /> Associated Malware
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {actor.malware.map((m) => (
                  <span
                    key={m}
                    className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-destructive/15 text-destructive"
                  >
                    {m}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Techniques */}
          {actor.techniques.length > 0 && (
            <div>
              <h4 className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Target className="h-3 w-3" /> Attack Techniques
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {actor.techniques.slice(0, 20).map((t) => (
                  <span
                    key={t.id}
                    className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-[hsl(45,100%,50%)]/15 text-warning"
                  >
                    {t.id} {t.name}
                  </span>
                ))}
                {actor.techniques.length > 20 && (
                  <span className="font-mono text-[10px] text-muted-foreground">
                    +{actor.techniques.length - 20} more
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Industries */}
          {actor.industries.length > 0 && (
            <div>
              <h4 className="font-mono text-[10px] text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
                <Building2 className="h-3 w-3" /> Targeted Industries
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {actor.industries.map((ind) => (
                  <span
                    key={ind}
                    className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-primary/15 text-primary"
                  >
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          )}

          {actor.url && (
            <a
              href={actor.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block font-mono text-xs text-secondary hover:underline"
            >
              View on MITRE ATT&CK →
            </a>
          )}
        </div>
      )}
    </div>
  );
}

export default function ThreatActors() {
  const [search, setSearch] = useState("");

  const { data: actors, isLoading, isError } = useQuery({
    queryKey: ["threat-actors"],
    queryFn: fetchThreatActors,
    staleTime: 30 * 60 * 1000,
  });

  const filtered = useMemo(() => {
    if (!actors) return [];
    if (!search) return actors;
    const q = search.toLowerCase();
    return actors.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.aliases.some((al) => al.toLowerCase().includes(q)) ||
        a.malware.some((m) => m.toLowerCase().includes(q)) ||
        a.industries.some((i) => i.toLowerCase().includes(q))
    );
  }, [actors, search]);

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
              <span className="font-mono text-xs text-muted-foreground">/ Threat Actors</span>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-4 cyber-grid overflow-auto">
            {/* Stats */}
            {actors && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-card border border-border rounded-lg p-4">
                  <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Threat Groups</p>
                  <p className="font-mono text-3xl font-bold text-destructive mt-1">{actors.length}</p>
                </div>
                <div className="bg-card border border-border rounded-lg p-4">
                  <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Unique Malware</p>
                  <p className="font-mono text-3xl font-bold text-warning mt-1">
                    {new Set(actors.flatMap((a) => a.malware)).size}
                  </p>
                </div>
                <div className="bg-card border border-border rounded-lg p-4">
                  <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Unique Techniques</p>
                  <p className="font-mono text-3xl font-bold text-secondary mt-1">
                    {new Set(actors.flatMap((a) => a.techniques.map((t) => t.id))).size}
                  </p>
                </div>
              </div>
            )}

            {/* Search */}
            <div className="bg-card border border-border rounded-lg p-4">
              <div className="flex gap-3 items-center">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search by name, alias, malware, or industry..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="pl-9 font-mono text-sm bg-muted border-border"
                  />
                </div>
                <span className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                  {filtered.length} actors
                </span>
              </div>
            </div>

            {/* Loading */}
            {isLoading && (
              <div className="space-y-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-20 w-full" />
                ))}
              </div>
            )}

            {isError && (
              <div className="bg-card border border-destructive/50 rounded-lg p-8 text-center">
                <p className="font-mono text-sm text-destructive">Failed to load threat actor data.</p>
              </div>
            )}

            {/* Actor List */}
            {!isLoading && !isError && (
              <div className="space-y-2">
                {filtered.length === 0 && (
                  <p className="font-mono text-sm text-muted-foreground text-center py-8">
                    No threat actors match your search.
                  </p>
                )}
                {filtered.map((actor) => (
                  <ActorCard key={actor.name} actor={actor} />
                ))}
              </div>
            )}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
