import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";

const timeData = [
  { name: "Mon", threats: 24, blocked: 22 },
  { name: "Tue", threats: 31, blocked: 28 },
  { name: "Wed", threats: 18, blocked: 17 },
  { name: "Thu", threats: 45, blocked: 40 },
  { name: "Fri", threats: 38, blocked: 35 },
  { name: "Sat", threats: 12, blocked: 12 },
  { name: "Sun", threats: 8, blocked: 7 },
];

const attackTypes = [
  { name: "Phishing", value: 35 },
  { name: "Malware", value: 25 },
  { name: "DDoS", value: 15 },
  { name: "Ransomware", value: 12 },
  { name: "Zero-Day", value: 8 },
  { name: "Other", value: 5 },
];

const severityData = [
  { name: "Critical", count: 12 },
  { name: "High", count: 28 },
  { name: "Medium", count: 45 },
  { name: "Low", count: 67 },
  { name: "Info", count: 120 },
];

const COLORS = [
  "hsl(0, 85%, 55%)",
  "hsl(45, 100%, 50%)",
  "hsl(190, 100%, 45%)",
  "hsl(280, 100%, 60%)",
  "hsl(160, 100%, 45%)",
  "hsl(220, 10%, 55%)",
];

const tooltipStyle = {
  backgroundColor: "hsl(220, 18%, 10%)",
  border: "1px solid hsl(160, 30%, 18%)",
  borderRadius: "8px",
  fontFamily: "JetBrains Mono, monospace",
  fontSize: "12px",
};

export function AnalyticsCharts() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      {/* Threat Timeline */}
      <div className="lg:col-span-2 bg-card border border-border rounded-lg p-4">
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
          Threat Activity (7 Days)
        </h3>
        <ResponsiveContainer width="100%" height={240}>
          <AreaChart data={timeData}>
            <defs>
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(0, 85%, 55%)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="hsl(0, 85%, 55%)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(160, 100%, 45%)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="hsl(160, 100%, 45%)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(160, 30%, 18%)" />
            <XAxis dataKey="name" tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 11 }} />
            <YAxis tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 11 }} />
            <Tooltip contentStyle={tooltipStyle} />
            <Area type="monotone" dataKey="threats" stroke="hsl(0, 85%, 55%)" fill="url(#threatGrad)" strokeWidth={2} />
            <Area type="monotone" dataKey="blocked" stroke="hsl(160, 100%, 45%)" fill="url(#blockedGrad)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Attack Types */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
          Attack Vectors
        </h3>
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie data={attackTypes} cx="50%" cy="50%" innerRadius={55} outerRadius={80} dataKey="value" paddingAngle={3}>
              {attackTypes.map((_, i) => (
                <Cell key={i} fill={COLORS[i]} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
          </PieChart>
        </ResponsiveContainer>
        <div className="grid grid-cols-2 gap-1 mt-2">
          {attackTypes.map((a, i) => (
            <div key={a.name} className="flex items-center gap-1.5">
              <div className="h-2 w-2 rounded-full" style={{ backgroundColor: COLORS[i] }} />
              <span className="font-mono text-xs text-muted-foreground">{a.name}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Severity Distribution */}
      <div className="lg:col-span-3 bg-card border border-border rounded-lg p-4">
        <h3 className="font-mono text-sm font-semibold text-foreground uppercase tracking-wider mb-4">
          Alert Severity Distribution
        </h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={severityData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(160, 30%, 18%)" horizontal={false} />
            <XAxis type="number" tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 11 }} />
            <YAxis dataKey="name" type="category" tick={{ fill: "hsl(220, 10%, 55%)", fontFamily: "JetBrains Mono", fontSize: 11 }} width={70} />
            <Tooltip contentStyle={tooltipStyle} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {severityData.map((_, i) => (
                <Cell key={i} fill={COLORS[i]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
