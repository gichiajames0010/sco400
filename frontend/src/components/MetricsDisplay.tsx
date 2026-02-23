/**
 * MetricsDisplay — renders a grid of metric cards summarising the analysis.
 *
 * Each card shows one of the six metrics returned by the backend:
 *   total_rules, redundant_rules, shadowed_rules, conflicting_pairs,
 *   optimized_rule_count, and reduction_ratio.
 *
 * Cards are configured via an array so adding a new metric requires
 * only appending a single entry to the `cards` array.
 */
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
      // redundant_rules: rules fully covered by an earlier rule with the same action
      value: metrics.redundant_rules,
      icon: Copy,
      color: 'text-warning',
      bgColor: 'bg-warning/10',
    },
    {
      label: 'Shadowed Rules',
      // shadowed_rules: unreachable rules covered by an earlier rule with a different action
      value: metrics.shadowed_rules,
      icon: EyeOff,
      color: 'text-muted-foreground',
      bgColor: 'bg-muted',
    },
    {
      label: 'Conflicting Rules',
      // conflicting_pairs: count of rule pairs with overlapping traffic but opposing actions
      value: metrics.conflicting_pairs,
      icon: AlertTriangle,
      color: 'text-destructive',
      bgColor: 'bg-destructive/10',
    },
    {
      label: 'Optimized Count',
      // optimized_rule_count: rules remaining after redundant/shadowed rules are removed
      value: metrics.optimized_rule_count,
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
