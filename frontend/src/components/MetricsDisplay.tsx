import { 
  Layers, 
  Copy, 
  EyeOff, 
  AlertTriangle, 
  CheckCircle, 
  TrendingDown 
} from 'lucide-react';
import type { RuleMetrics } from '../services/api';

interface MetricsDisplayProps {
  metrics: RuleMetrics;
}

/**
 * MetricsDisplay Component
 * 
 * Displays analysis metrics in a grid of visual cards.
 * Each card represents a different metric from the analysis.
 */
export function MetricsDisplay({ metrics }: MetricsDisplayProps) {
  // Calculate reduction percentage for display
  const reductionPercent = (metrics.reduction_ratio * 100).toFixed(1);

  // Metric card configurations
  const cards = [
    {
      label: 'Total Rules',
      value: metrics.total_rules,
      icon: Layers,
      color: 'text-primary',
      bgColor: 'bg-primary/10',
    },
    {
      label: 'Redundant Rules',
      value: metrics.redundant_count,
      icon: Copy,
      color: 'text-warning',
      bgColor: 'bg-warning/10',
    },
    {
      label: 'Shadowed Rules',
      value: metrics.shadowed_count,
      icon: EyeOff,
      color: 'text-muted-foreground',
      bgColor: 'bg-muted',
    },
    {
      label: 'Conflicting Rules',
      value: metrics.conflict_count,
      icon: AlertTriangle,
      color: 'text-destructive',
      bgColor: 'bg-destructive/10',
    },
    {
      label: 'Optimized Count',
      value: metrics.optimized_count,
      icon: CheckCircle,
      color: 'text-success',
      bgColor: 'bg-success/10',
    },
    {
      label: 'Rule Reduction',
      value: `${reductionPercent}%`,
      icon: TrendingDown,
      color: 'text-success',
      bgColor: 'bg-success/10',
    },
  ];

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-primary/10 rounded-lg">
          <Layers className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h2 className="section-title">Analysis Metrics</h2>
          <p className="section-subtitle">
            Overview of your firewall ruleset analysis
          </p>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {cards.map((card) => (
          <div key={card.label} className="metric-card">
            {/* Icon */}
            <div className={`p-2 ${card.bgColor} rounded-lg w-fit`}>
              <card.icon className={`w-5 h-5 ${card.color}`} />
            </div>
            
            {/* Value */}
            <div className={`text-2xl font-bold ${card.color}`}>
              {card.value}
            </div>
            
            {/* Label */}
            <div className="text-sm text-muted-foreground">
              {card.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
