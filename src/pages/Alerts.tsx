import { useState } from "react";
import { Shield, Bell, BellOff, CheckCheck, Trash2, AlertTriangle, ExternalLink } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { useAlerts } from "@/stores/alertStore";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const sevBadge: Record<string, string> = {
  CRITICAL: "bg-destructive/20 text-destructive",
  HIGH: "bg-[hsl(45,100%,50%)]/20 text-warning",
};

export default function Alerts() {
  const { alerts, markRead, markAllRead, dismiss, clearAll, unreadCount } = useAlerts();
  const [filter, setFilter] = useState<"all" | "unread" | "CRITICAL" | "HIGH">("all");

  const filtered = alerts
    .filter((a) => !a.dismissed)
    .filter((a) => {
      if (filter === "unread") return !a.read;
      if (filter === "CRITICAL" || filter === "HIGH") return a.severity === filter;
      return true;
    });

  const unread = unreadCount();

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
              <span className="font-mono text-xs text-muted-foreground">/ Alerts</span>
            </div>
            {unread > 0 && (
              <div className="ml-auto flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-destructive animate-pulse" />
                <span className="font-mono text-xs text-destructive">{unread} unread</span>
              </div>
            )}
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-4 cyber-grid overflow-auto">
            {/* Stats & Actions */}
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="grid grid-cols-3 gap-3 flex-1">
                <div className="bg-card border border-border rounded-lg p-4 text-center">
                  <p className="font-mono text-2xl font-bold text-destructive">{unread}</p>
                  <p className="font-mono text-[10px] text-muted-foreground uppercase">Unread</p>
                </div>
                <div className="bg-card border border-border rounded-lg p-4 text-center">
                  <p className="font-mono text-2xl font-bold text-warning">
                    {alerts.filter((a) => a.severity === "CRITICAL" && !a.dismissed).length}
                  </p>
                  <p className="font-mono text-[10px] text-muted-foreground uppercase">Critical</p>
                </div>
                <div className="bg-card border border-border rounded-lg p-4 text-center">
                  <p className="font-mono text-2xl font-bold text-foreground">
                    {alerts.filter((a) => !a.dismissed).length}
                  </p>
                  <p className="font-mono text-[10px] text-muted-foreground uppercase">Total</p>
                </div>
              </div>
            </div>

            {/* Filter & Bulk Actions */}
            <div className="bg-card border border-border rounded-lg p-4 flex flex-col sm:flex-row items-center gap-3">
              <Select value={filter} onValueChange={(v: any) => setFilter(v)}>
                <SelectTrigger className="w-[160px] font-mono text-xs bg-muted border-border">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Alerts</SelectItem>
                  <SelectItem value="unread">Unread Only</SelectItem>
                  <SelectItem value="CRITICAL">Critical</SelectItem>
                  <SelectItem value="HIGH">High</SelectItem>
                </SelectContent>
              </Select>
              <div className="flex gap-2 ml-auto">
                <Button variant="outline" size="sm" onClick={markAllRead} className="font-mono text-xs">
                  <CheckCheck className="h-3.5 w-3.5 mr-1" /> Mark All Read
                </Button>
                <Button variant="outline" size="sm" onClick={clearAll} className="font-mono text-xs text-destructive hover:text-destructive">
                  <Trash2 className="h-3.5 w-3.5 mr-1" /> Clear All
                </Button>
              </div>
            </div>

            {/* Info banner */}
            <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 flex items-start gap-3">
              <Bell className="h-4 w-4 text-primary mt-0.5 shrink-0" />
              <div>
                <p className="font-mono text-xs text-foreground font-bold">Automatic CVE Monitoring Active</p>
                <p className="font-mono text-[10px] text-muted-foreground mt-0.5">
                  The system polls NVD every 5 minutes for new critical and high severity CVEs (CVSS ≥ 7.0).
                  Toast notifications appear for critical CVEs (CVSS ≥ 9.0).
                </p>
              </div>
            </div>

            {/* Alert List */}
            {filtered.length === 0 ? (
              <div className="bg-card border border-border rounded-lg p-12 text-center">
                <BellOff className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
                <p className="font-mono text-sm text-muted-foreground">No alerts to display.</p>
                <p className="font-mono text-xs text-muted-foreground mt-1">
                  Critical CVE alerts will appear here automatically.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {filtered.map((alert) => (
                  <div
                    key={alert.id}
                    className={`bg-card border rounded-lg p-4 transition-colors ${
                      alert.read
                        ? "border-border opacity-70"
                        : alert.severity === "CRITICAL"
                        ? "border-destructive/40 glow-destructive"
                        : "border-[hsl(45,100%,50%)]/40"
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`p-1.5 rounded-md mt-0.5 ${
                        alert.severity === "CRITICAL" ? "bg-destructive/10" : "bg-[hsl(45,100%,50%)]/10"
                      }`}>
                        <AlertTriangle className={`h-4 w-4 ${
                          alert.severity === "CRITICAL" ? "text-destructive" : "text-warning"
                        }`} />
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          {!alert.read && (
                            <div className="h-2 w-2 rounded-full bg-primary shrink-0" />
                          )}
                          <span className={`font-mono text-[10px] px-2 py-0.5 rounded-full ${sevBadge[alert.severity]}`}>
                            {alert.severity}
                          </span>
                          <span className="font-mono text-[10px] text-muted-foreground">
                            CVSS {alert.cvss}
                          </span>
                          <span className="font-mono text-[10px] text-muted-foreground">
                            · {new Date(alert.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <h4 className="font-mono text-sm font-bold text-foreground mb-1">
                          {alert.cveId}
                        </h4>
                        <p className="font-mono text-xs text-muted-foreground leading-relaxed line-clamp-2">
                          {alert.description}
                        </p>
                      </div>

                      <div className="flex items-center gap-1 shrink-0">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${alert.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1.5 text-muted-foreground hover:text-primary transition-colors"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                        </a>
                        {!alert.read && (
                          <button
                            onClick={() => markRead(alert.id)}
                            className="p-1.5 text-muted-foreground hover:text-primary transition-colors"
                            title="Mark as read"
                          >
                            <CheckCheck className="h-3.5 w-3.5" />
                          </button>
                        )}
                        <button
                          onClick={() => dismiss(alert.id)}
                          className="p-1.5 text-muted-foreground hover:text-destructive transition-colors"
                          title="Dismiss"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
