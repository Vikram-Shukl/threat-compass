import { create } from "zustand";

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

interface AlertStore {
  alerts: CveAlert[];
  seenIds: Set<string>;
  addAlerts: (alerts: CveAlert[]) => void;
  markRead: (id: string) => void;
  markAllRead: () => void;
  dismiss: (id: string) => void;
  clearAll: () => void;
  unreadCount: () => number;
}

// Load persisted alerts from localStorage
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
    return raw ? new Set(JSON.parse(raw)) : new Set();
  } catch {
    return new Set();
  }
}

function persist(alerts: CveAlert[], seenIds: Set<string>) {
  localStorage.setItem("sentinel-cve-alerts", JSON.stringify(alerts.slice(0, 100)));
  localStorage.setItem("sentinel-seen-cve-ids", JSON.stringify([...seenIds].slice(-500)));
}

export const useAlertStore = create<AlertStore>((set, get) => ({
  alerts: loadAlerts(),
  seenIds: loadSeenIds(),

  addAlerts: (newAlerts) =>
    set((state) => {
      const seenIds = new Set(state.seenIds);
      const toAdd = newAlerts.filter((a) => !seenIds.has(a.cveId));
      if (toAdd.length === 0) return state;

      for (const a of toAdd) seenIds.add(a.cveId);
      const alerts = [...toAdd, ...state.alerts].slice(0, 100);
      persist(alerts, seenIds);
      return { alerts, seenIds };
    }),

  markRead: (id) =>
    set((state) => {
      const alerts = state.alerts.map((a) =>
        a.id === id ? { ...a, read: true } : a
      );
      persist(alerts, state.seenIds);
      return { alerts };
    }),

  markAllRead: () =>
    set((state) => {
      const alerts = state.alerts.map((a) => ({ ...a, read: true }));
      persist(alerts, state.seenIds);
      return { alerts };
    }),

  dismiss: (id) =>
    set((state) => {
      const alerts = state.alerts.map((a) =>
        a.id === id ? { ...a, dismissed: true } : a
      );
      persist(alerts, state.seenIds);
      return { alerts };
    }),

  clearAll: () =>
    set((state) => {
      persist([], state.seenIds);
      return { alerts: [] };
    }),

  unreadCount: () => get().alerts.filter((a) => !a.read && !a.dismissed).length,
}));
