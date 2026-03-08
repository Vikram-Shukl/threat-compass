import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchThreatFox } from "@/lib/threatfoxApi";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  ZoomableGroup,
} from "react-simple-maps";
import { Shield, Globe, AlertTriangle } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

interface GeoIp {
  ip: string;
  lat: number;
  lng: number;
  country: string;
  countryCode: string;
}

interface CountryStats {
  country: string;
  code: string;
  count: number;
  ips: string[];
}

async function fetchThreatGeoData(): Promise<{
  markers: GeoIp[];
  byCountry: CountryStats[];
  total: number;
}> {
  // 1. Get IPs from ThreatFox
  const tfRes = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_iocs", days: 7 }),
  });
  if (!tfRes.ok) throw new Error("Failed to fetch threat data");
  const tfData = await tfRes.json();

  if (tfData.query_status !== "ok" || !tfData.data) {
    return { markers: [], byCountry: [], total: 0 };
  }

  // Extract unique IPs
  const ipSet = new Set<string>();
  for (const ioc of tfData.data) {
    const raw = ioc.ioc ?? "";
    // Match ip:port or plain IP
    const match = raw.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (match) ipSet.add(match[1]);
  }

  const ips = Array.from(ipSet).slice(0, 80); // Limit for free API
  if (ips.length === 0) return { markers: [], byCountry: [], total: 0 };

  // 2. Batch geolocate via ip-api.com (free, 15 per batch for CORS-free)
  const markers: GeoIp[] = [];
  const batches = [];
  for (let i = 0; i < ips.length; i += 100) {
    batches.push(ips.slice(i, i + 100));
  }

  for (const batch of batches) {
    try {
      const geoRes = await fetch("http://ip-api.com/batch?fields=query,lat,lon,country,countryCode,status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batch.map((ip) => ({ query: ip }))),
      });
      if (geoRes.ok) {
        const results = await geoRes.json();
        for (const r of results) {
          if (r.status === "success" && r.lat && r.lon) {
            markers.push({
              ip: r.query,
              lat: r.lat,
              lng: r.lon,
              country: r.country,
              countryCode: r.countryCode,
            });
          }
        }
      }
    } catch {
      // Continue with what we have
    }
  }

  // 3. Aggregate by country
  const countryMap: Record<string, CountryStats> = {};
  for (const m of markers) {
    if (!countryMap[m.countryCode]) {
      countryMap[m.countryCode] = {
        country: m.country,
        code: m.countryCode,
        count: 0,
        ips: [],
      };
    }
    countryMap[m.countryCode].count++;
    if (countryMap[m.countryCode].ips.length < 5) {
      countryMap[m.countryCode].ips.push(m.ip);
    }
  }

  const byCountry = Object.values(countryMap).sort((a, b) => b.count - a.count);

  return { markers, byCountry, total: markers.length };
}

function markerSize(total: number): number {
  return Math.max(3, Math.min(8, 3 + total * 0.5));
}

export default function ThreatMap() {
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["threat-geo-map"],
    queryFn: fetchThreatGeoData,
    staleTime: 12 * 60 * 60 * 1000,
    refetchInterval: 12 * 60 * 60 * 1000,
  });

  const countryCodeSet = useMemo(() => {
    if (!data) return new Set<string>();
    return new Set(data.byCountry.map((c) => c.code));
  }, [data]);

  const countryLookup = useMemo(() => {
    if (!data) return {};
    const map: Record<string, CountryStats> = {};
    for (const c of data.byCountry) map[c.code] = c;
    return map;
  }, [data]);

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
              <span className="font-mono text-xs text-muted-foreground">/ Threat Map</span>
            </div>
            {data && (
              <div className="ml-auto flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-destructive animate-pulse" />
                <span className="font-mono text-xs text-muted-foreground hidden sm:inline">
                  {data.total} malicious IPs tracked
                </span>
              </div>
            )}
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-4 cyber-grid overflow-auto">
            {/* Map */}
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="p-4 border-b border-border">
                <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">
                  Global Threat Map
                  <span className="text-xs text-muted-foreground ml-2 normal-case">
                    malicious IP geolocation (7 days)
                  </span>
                </h3>
              </div>

              {isLoading && <Skeleton className="h-[450px] w-full" />}

              {isError && (
                <div className="h-[450px] flex items-center justify-center">
                  <p className="font-mono text-sm text-destructive">Failed to load threat geolocation data.</p>
                </div>
              )}

              {data && (
                <div className="relative">
                  <ComposableMap
                    projectionConfig={{ rotate: [-10, 0, 0], scale: 147 }}
                    style={{ width: "100%", height: "auto" }}
                  >
                    <ZoomableGroup>
                      <Geographies geography={GEO_URL}>
                        {({ geographies }) =>
                          geographies.map((geo) => {
                            const iso = geo.properties?.ISO_A2 ?? geo.id;
                            const isAttackSource = countryCodeSet.has(iso);
                            const stats = countryLookup[iso];
                            const isHovered = hoveredCountry === iso;

                            return (
                              <Geography
                                key={geo.rpiKey}
                                geography={geo}
                                onMouseEnter={() => setHoveredCountry(iso)}
                                onMouseLeave={() => setHoveredCountry(null)}
                                style={{
                                  default: {
                                    fill: isAttackSource
                                      ? `hsl(0, ${Math.min(85, 30 + (stats?.count ?? 0) * 8)}%, ${Math.max(25, 55 - (stats?.count ?? 0) * 4)}%)`
                                      : "hsl(220, 15%, 12%)",
                                    stroke: "hsl(160, 30%, 18%)",
                                    strokeWidth: 0.5,
                                    outline: "none",
                                  },
                                  hover: {
                                    fill: isAttackSource
                                      ? "hsl(0, 85%, 45%)"
                                      : "hsl(220, 15%, 18%)",
                                    stroke: "hsl(160, 100%, 45%)",
                                    strokeWidth: 1,
                                    outline: "none",
                                  },
                                  pressed: { outline: "none" },
                                }}
                              />
                            );
                          })
                        }
                      </Geographies>

                      {/* IP Markers */}
                      {data.markers.map((m, i) => (
                        <Marker key={`${m.ip}-${i}`} coordinates={[m.lng, m.lat]}>
                          <circle
                            r={3}
                            fill="hsl(0, 85%, 55%)"
                            fillOpacity={0.7}
                            stroke="hsl(0, 85%, 65%)"
                            strokeWidth={0.5}
                          />
                          <circle
                            r={6}
                            fill="none"
                            stroke="hsl(0, 85%, 55%)"
                            strokeWidth={0.3}
                            strokeOpacity={0.4}
                          />
                        </Marker>
                      ))}
                    </ZoomableGroup>
                  </ComposableMap>

                  {/* Hover tooltip */}
                  {hoveredCountry && countryLookup[hoveredCountry] && (
                    <div className="absolute top-4 right-4 bg-card/95 border border-border rounded-lg p-3 backdrop-blur-sm">
                      <p className="font-mono text-xs font-bold text-foreground">
                        {countryLookup[hoveredCountry].country}
                      </p>
                      <p className="font-mono text-xs text-destructive mt-1">
                        {countryLookup[hoveredCountry].count} malicious IPs
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Attack Source Distribution */}
            {data && data.byCountry.length > 0 && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Country Table */}
                <div className="bg-card border border-border rounded-lg overflow-hidden">
                  <div className="p-4 border-b border-border">
                    <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider">
                      Attack Source by Country
                    </h3>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-border">
                          {["#", "Country", "IPs", "Distribution"].map((h) => (
                            <th
                              key={h}
                              className="px-4 py-2 text-left font-mono text-xs text-muted-foreground uppercase tracking-wider"
                            >
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {data.byCountry.slice(0, 15).map((c, i) => {
                          const pct = Math.round((c.count / data.total) * 100);
                          return (
                            <tr key={c.code} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                              <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{i + 1}</td>
                              <td className="px-4 py-2 font-mono text-sm text-foreground">
                                {c.country}
                              </td>
                              <td className="px-4 py-2 font-mono text-sm text-destructive font-bold">{c.count}</td>
                              <td className="px-4 py-2 w-40">
                                <div className="flex items-center gap-2">
                                  <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                                    <div
                                      className="h-full bg-destructive rounded-full"
                                      style={{ width: `${pct}%` }}
                                    />
                                  </div>
                                  <span className="font-mono text-[10px] text-muted-foreground w-8 text-right">
                                    {pct}%
                                  </span>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Stats Summary */}
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-card border border-border rounded-lg p-4">
                      <Globe className="h-5 w-5 text-primary mb-2" />
                      <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Countries</p>
                      <p className="font-mono text-3xl font-bold text-foreground mt-1">{data.byCountry.length}</p>
                    </div>
                    <div className="bg-card border border-border rounded-lg p-4">
                      <AlertTriangle className="h-5 w-5 text-destructive mb-2" />
                      <p className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Total IPs</p>
                      <p className="font-mono text-3xl font-bold text-destructive mt-1">{data.total}</p>
                    </div>
                  </div>

                  {/* Top 5 IPs */}
                  <div className="bg-card border border-border rounded-lg p-4">
                    <h4 className="font-mono text-xs text-muted-foreground uppercase tracking-wider mb-3">
                      Sample Malicious IPs
                    </h4>
                    <div className="space-y-2">
                      {data.markers.slice(0, 8).map((m) => (
                        <div
                          key={m.ip}
                          className="flex items-center justify-between py-1 border-b border-border/30 last:border-0"
                        >
                          <span className="font-mono text-xs text-foreground">{m.ip}</span>
                          <span className="font-mono text-[10px] text-muted-foreground">{m.country}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
