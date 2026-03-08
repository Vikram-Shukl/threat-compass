import { Shield, Bug, AlertTriangle, Activity, ShieldCheck, Eye } from "lucide-react";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { StatCard } from "@/components/StatCard";
import { CveTable } from "@/components/CveTable";
import { ThreatFeed } from "@/components/ThreatFeed";
import { MitreGrid } from "@/components/MitreGrid";
import { AnalyticsCharts } from "@/components/AnalyticsCharts";
import { CveSeverityChart } from "@/components/CveSeverityChart";

const Index = () => {
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
              <span className="font-mono text-xs text-muted-foreground">/ Dashboard</span>
            </div>
            <div className="ml-auto flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-primary animate-pulse-glow" />
                <span className="font-mono text-xs text-muted-foreground hidden sm:inline">Monitoring Active</span>
              </div>
            </div>
          </header>

          <main className="flex-1 p-4 md:p-6 space-y-6 cyber-grid overflow-auto">
            {/* Overview Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard icon={AlertTriangle} title="Active Threats" value={23} change="↑ 12% from yesterday" changeType="up" glowClass="glow-destructive" />
              <StatCard icon={Bug} title="New CVEs (24h)" value={7} change="↓ 3 from last week" changeType="down" />
              <StatCard icon={Eye} title="IOCs Tracked" value="1,247" change="42 added today" />
              <StatCard icon={ShieldCheck} title="Threats Blocked" value="98.2%" change="↑ 0.3% improvement" changeType="down" />
            </div>

            {/* CVEs & Threat Feed */}
            <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
              <div className="xl:col-span-3">
                <CveTable />
              </div>
              <div className="xl:col-span-2">
                <ThreatFeed />
              </div>
            </div>

            {/* MITRE ATT&CK */}
            <MitreGrid />

            {/* CVE Severity Distribution */}
            <CveSeverityChart />

            {/* Analytics */}
            <AnalyticsCharts />
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
};

export default Index;
