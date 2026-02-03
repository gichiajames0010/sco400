import { Copy, EyeOff, AlertTriangle, ChevronRight } from 'lucide-react';
import type { FirewallRule, RuleConflict } from '../services/api';

interface AnomalyTablesProps {
  redundantRules: FirewallRule[];
  shadowedRules: FirewallRule[];
  conflicts: RuleConflict[];
}

/**
 * RuleRow Component
 * 
 * Displays a single firewall rule with its metadata
 */
function RuleRow({ rule }: { rule: FirewallRule }) {
  return (
    <div className="p-3 border-b border-border last:border-b-0 hover:bg-muted/30 transition-colors">
      <div className="flex items-start gap-4">
        {/* Rule Order */}
        <div className="flex-shrink-0 w-12 text-center">
          <span className="inline-flex items-center justify-center w-8 h-8 bg-muted rounded-full text-sm font-mono text-muted-foreground">
            #{rule.order}
          </span>
        </div>
        
        {/* Rule Details */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-xs font-medium bg-secondary rounded">
              {rule.chain}
            </span>
            <span className={`px-2 py-0.5 text-xs font-medium rounded ${
              rule.action === 'ACCEPT' 
                ? 'bg-success/20 text-success' 
                : rule.action === 'DROP' || rule.action === 'REJECT'
                ? 'bg-destructive/20 text-destructive'
                : 'bg-muted text-muted-foreground'
            }`}>
              {rule.action}
            </span>
          </div>
          <code className="rule-display text-xs">
            {rule.raw}
          </code>
        </div>
      </div>
    </div>
  );
}

/**
 * ConflictPair Component
 * 
 * Displays two conflicting rules side by side
 */
function ConflictPair({ conflict }: { conflict: RuleConflict }) {
  return (
    <div className="p-4 border-b border-border last:border-b-0">
      <div className="grid md:grid-cols-2 gap-4">
        {/* Rule 1 */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center justify-center w-6 h-6 bg-destructive/20 rounded-full text-xs font-mono text-destructive">
              #{conflict.rule1.order}
            </span>
            <span className="px-2 py-0.5 text-xs font-medium bg-secondary rounded">
              {conflict.rule1.chain}
            </span>
            <span className={`px-2 py-0.5 text-xs font-medium rounded ${
              conflict.rule1.action === 'ACCEPT' 
                ? 'bg-success/20 text-success' 
                : 'bg-destructive/20 text-destructive'
            }`}>
              {conflict.rule1.action}
            </span>
          </div>
          <code className="rule-display text-xs">
            {conflict.rule1.raw}
          </code>
        </div>

        {/* Conflict Indicator */}
        <div className="hidden md:flex items-center justify-center absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
          <ChevronRight className="w-5 h-5 text-destructive" />
        </div>

        {/* Rule 2 */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center justify-center w-6 h-6 bg-destructive/20 rounded-full text-xs font-mono text-destructive">
              #{conflict.rule2.order}
            </span>
            <span className="px-2 py-0.5 text-xs font-medium bg-secondary rounded">
              {conflict.rule2.chain}
            </span>
            <span className={`px-2 py-0.5 text-xs font-medium rounded ${
              conflict.rule2.action === 'ACCEPT' 
                ? 'bg-success/20 text-success' 
                : 'bg-destructive/20 text-destructive'
            }`}>
              {conflict.rule2.action}
            </span>
          </div>
          <code className="rule-display text-xs">
            {conflict.rule2.raw}
          </code>
        </div>
      </div>
      
      {/* Conflict Reason */}
      {conflict.reason && (
        <div className="mt-3 text-xs text-muted-foreground italic">
          {conflict.reason}
        </div>
      )}
    </div>
  );
}

/**
 * EmptyState Component
 * 
 * Shows when no anomalies are found
 */
function EmptyState({ message }: { message: string }) {
  return (
    <div className="p-6 text-center text-muted-foreground text-sm">
      {message}
    </div>
  );
}

/**
 * AnomalyTables Component
 * 
 * Displays three panels for different types of rule anomalies:
 * - Redundant Rules
 * - Shadowed Rules
 * - Conflicting Rules
 */
export function AnomalyTables({ redundantRules, shadowedRules, conflicts }: AnomalyTablesProps) {
  return (
    <div className="space-y-6">
      {/* Section Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-warning/10 rounded-lg">
          <AlertTriangle className="w-5 h-5 text-warning" />
        </div>
        <div>
          <h2 className="section-title">Anomaly Analysis</h2>
          <p className="section-subtitle">
            Detected issues in your firewall ruleset
          </p>
        </div>
      </div>

      {/* Anomaly Panels Grid */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* Redundant Rules Panel */}
        <div className="anomaly-panel">
          <div className="anomaly-header-redundant">
            <Copy className="w-4 h-4" />
            Redundant Rules
            <span className="ml-auto bg-warning/20 px-2 py-0.5 rounded text-xs">
              {redundantRules.length}
            </span>
          </div>
          <div className="max-h-80 overflow-y-auto scrollbar-cyber">
            {redundantRules.length > 0 ? (
              redundantRules.map((rule, index) => (
                <RuleRow key={`redundant-${index}`} rule={rule} />
              ))
            ) : (
              <EmptyState message="No redundant rules detected" />
            )}
          </div>
        </div>

        {/* Shadowed Rules Panel */}
        <div className="anomaly-panel">
          <div className="anomaly-header-shadowed">
            <EyeOff className="w-4 h-4" />
            Shadowed Rules
            <span className="ml-auto bg-muted-foreground/20 px-2 py-0.5 rounded text-xs">
              {shadowedRules.length}
            </span>
          </div>
          <div className="max-h-80 overflow-y-auto scrollbar-cyber">
            {shadowedRules.length > 0 ? (
              shadowedRules.map((rule, index) => (
                <RuleRow key={`shadowed-${index}`} rule={rule} />
              ))
            ) : (
              <EmptyState message="No shadowed rules detected" />
            )}
          </div>
        </div>

        {/* Conflicting Rules Panel */}
        <div className="anomaly-panel">
          <div className="anomaly-header-conflict">
            <AlertTriangle className="w-4 h-4" />
            Rule Conflicts
            <span className="ml-auto bg-destructive/20 px-2 py-0.5 rounded text-xs">
              {conflicts.length}
            </span>
          </div>
          <div className="max-h-80 overflow-y-auto scrollbar-cyber">
            {conflicts.length > 0 ? (
              conflicts.map((conflict, index) => (
                <ConflictPair key={`conflict-${index}`} conflict={conflict} />
              ))
            ) : (
              <EmptyState message="No conflicting rules detected" />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
