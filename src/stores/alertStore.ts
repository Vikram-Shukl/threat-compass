import { useCallback, useSyncExternalStore } from "react";

export interface CveAlert {
  id: string;
  cveId: string;
  title: string;
  description: string;
  severity: string;
  cvss: number;
  published: string;
  timestamp: number;
  read: boolean;
  dismissed: boolean;
}

// Simple store without zustand
let alerts: CveAlert[] = [];
let seenIds = new Set<string>();
const listeners = new Set<() => void>();

function notify() {
  for (const l of listeners) l();
}

function loadAlerts(): CveAlert[] {
  try {
    const raw = localStorage.getItem("sentinel-cve-alerts");
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function loadSeenIds(): Set<string> {
  try {
    const raw = localStorage.getItem("sentinel-seen-cve-ids");
    return raw ? new Set<string>(JSON.parse(raw)) : new Set<string>();
  } catch {
    return new Set<string>();
  }
}

function persist() {
  localStorage.setItem("sentinel-cve-alerts", JSON.stringify(alerts.slice(0, 100)));
  localStorage.setItem("sentinel-seen-cve-ids", JSON.stringify([...seenIds].slice(-500)));
}

// Initialize
alerts = loadAlerts();
seenIds = loadSeenIds();

export const alertActions = {
  addAlerts(newAlerts: CveAlert[]) {
    const toAdd = newAlerts.filter((a) => !seenIds.has(a.cveId));
    if (toAdd.length === 0) return;
    for (const a of toAdd) seenIds.add(a.cveId);
    alerts = [...toAdd, ...alerts].slice(0, 100);
    persist();
    notify();
  },
  markRead(id: string) {
    alerts = alerts.map((a) => (a.id === id ? { ...a, read: true } : a));
    persist();
    notify();
  },
  markAllRead() {
    alerts = alerts.map((a) => ({ ...a, read: true }));
    persist();
    notify();
  },
  dismiss(id: string) {
    alerts = alerts.map((a) => (a.id === id ? { ...a, dismissed: true } : a));
    persist();
    notify();
  },
  clearAll() {
    alerts = [];
    persist();
    notify();
  },
  getSeenIds() {
    return seenIds;
  },
};

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

function getSnapshot() {
  return alerts;
}

export function useAlerts() {
  const data = useSyncExternalStore(subscribe, getSnapshot);
  const unreadCount = data.filter((a) => !a.read && !a.dismissed).length;
  return { alerts: data, unreadCount, ...alertActions };
}
