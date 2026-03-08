import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: "up" | "down" | "neutral";
  icon: LucideIcon;
  glowClass?: string;
}

export function StatCard({ title, value, change, changeType = "neutral", icon: Icon, glowClass = "glow-primary" }: StatCardProps) {
  return (
    <div className={`bg-card border border-border rounded-lg p-5 ${glowClass} hover:border-primary/40 transition-all duration-300`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground mb-1">{title}</p>
          <p className="font-mono text-3xl font-bold text-foreground">{value}</p>
          {change && (
            <p className={`font-mono text-xs mt-1 ${
              changeType === "up" ? "text-destructive" : changeType === "down" ? "text-primary" : "text-muted-foreground"
            }`}>
              {change}
            </p>
          )}
        </div>
        <div className="p-2 bg-primary/10 rounded-md">
          <Icon className="h-5 w-5 text-primary" />
        </div>
      </div>
    </div>
  );
}
