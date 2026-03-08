import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useCveAlertPoller } from "@/hooks/useCveAlertPoller";
import Index from "./pages/Index";
import CveExplorer from "./pages/CveExplorer";
import ThreatIntel from "./pages/ThreatIntel";
import IpReputation from "./pages/IpReputation";
import MitreExplorer from "./pages/MitreExplorer";
import ThreatActors from "./pages/ThreatActors";
import ThreatMap from "./pages/ThreatMap";
import RiskScoring from "./pages/RiskScoring";
import AttackTimeline from "./pages/AttackTimeline";
import Alerts from "./pages/Alerts";
import Analytics from "./pages/Analytics";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

function AppRoutes() {
  useCveAlertPoller();

  return (
    <Routes>
      <Route path="/" element={<Index />} />
      <Route path="/cves" element={<CveExplorer />} />
      <Route path="/threats" element={<ThreatIntel />} />
      <Route path="/ip-reputation" element={<IpReputation />} />
      <Route path="/mitre" element={<MitreExplorer />} />
      <Route path="/actors" element={<ThreatActors />} />
      <Route path="/map" element={<ThreatMap />} />
      <Route path="/risk" element={<RiskScoring />} />
      <Route path="/timeline" element={<AttackTimeline />} />
      <Route path="/alerts" element={<Alerts />} />
      <Route path="/analytics" element={<Analytics />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
