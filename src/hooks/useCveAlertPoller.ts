import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { useAlertStore, CveAlert } from "@/stores/alertStore";

const POLL_INTERVAL = 5 * 60 * 1000; // 5 minutes
const CRITICAL_THRESHOLD = 9.0;
const HIGH_THRESHOLD = 7.0;

async function fetchRecentCriticalCves() {
  const res = await fetch(
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"
  );
  if (!res.ok) return [];
  const data = await res.json();

  const alerts: CveAlert[] = [];

  for (const v of data.vulnerabilities) {
    const cve = v.cve;
    const metrics = cve.metrics ?? {};
    const cvss31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const cvss30 = metrics.cvssMetricV30?.[0]?.cvssData;
    const cvss2 = metrics.cvssMetricV2?.[0]?.cvssData;
    const cvssData = cvss31 ?? cvss30 ?? cvss2;
    const score = cvssData?.baseScore ?? 0;

    if (score < HIGH_THRESHOLD) continue;

    const desc =
      cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? "";
    const severity = score >= CRITICAL_THRESHOLD ? "CRITICAL" : "HIGH";

    alerts.push({
      id: `alert-${cve.id}-${Date.now()}`,
      cveId: cve.id,
      title: `${severity} CVE: ${cve.id} (CVSS ${score})`,
      description: desc.length > 200 ? desc.slice(0, 200) + "…" : desc,
      severity,
      cvss: score,
      published: cve.published?.split("T")[0] ?? "",
      timestamp: Date.now(),
      read: false,
      dismissed: false,
    });
  }

  return alerts;
}

export function useCveAlertPoller() {
  const addAlerts = useAlertStore((s) => s.addAlerts);
  const hasNotified = useRef(false);

  const { data } = useQuery({
    queryKey: ["cve-alert-poll"],
    queryFn: fetchRecentCriticalCves,
    refetchInterval: POLL_INTERVAL,
    staleTime: POLL_INTERVAL - 10000,
  });

  useEffect(() => {
    if (!data || data.length === 0) return;

    const seenIds = useAlertStore.getState().seenIds;
    const newAlerts = data.filter((a) => !seenIds.has(a.cveId));

    if (newAlerts.length > 0) {
      addAlerts(newAlerts);

      // Show toast notifications for critical ones
      const criticals = newAlerts.filter((a) => a.severity === "CRITICAL");
      if (criticals.length > 0 && !hasNotified.current) {
        for (const alert of criticals.slice(0, 3)) {
          toast.error(alert.title, {
            description: alert.description.slice(0, 100) + "…",
            duration: 8000,
          });
        }
        if (criticals.length > 3) {
          toast.error(`+${criticals.length - 3} more critical CVEs detected`, {
            duration: 5000,
          });
        }
      }
      hasNotified.current = true;
    }
  }, [data, addAlerts]);
}
