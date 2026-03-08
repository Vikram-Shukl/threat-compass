import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
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
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
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
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
