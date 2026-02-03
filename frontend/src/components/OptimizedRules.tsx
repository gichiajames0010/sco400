import { CheckCircle, Download, Terminal } from 'lucide-react';
import type { FirewallRule } from '../services/api';
import { downloadRulesFile } from '../services/api';

interface OptimizedRulesProps {
  rules: FirewallRule[];
}

/**
 * OptimizedRules Component
 * 
 * Displays the optimized firewall ruleset with download capability.
 * Rules are shown in execution order, suitable for iptables-restore.
 */
export function OptimizedRules({ rules }: OptimizedRulesProps) {
  /**
   * Handles downloading the optimized rules as a text file
   */
  const handleDownload = () => {
    downloadRulesFile(rules, 'optimized_firewall_rules.txt');
  };

  return (
    <div className="cyber-card-glow overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border bg-success/5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-success/10 rounded-lg">
            <CheckCircle className="w-5 h-5 text-success" />
          </div>
          <div>
            <h2 className="section-title">Optimized Rule Set</h2>
            <p className="section-subtitle">
              {rules.length} rules in execution order
            </p>
          </div>
        </div>

        {/* Download Button */}
        <button
          onClick={handleDownload}
          className="btn-secondary"
          disabled={rules.length === 0}
        >
          <Download className="w-4 h-4" />
          Download Rules
        </button>
      </div>

      {/* Rules Display */}
      <div className="p-4">
        <div className="bg-input rounded-lg border border-border overflow-hidden">
          {/* Terminal Header */}
          <div className="px-4 py-2 bg-muted/50 border-b border-border flex items-center gap-2">
            <Terminal className="w-4 h-4 text-muted-foreground" />
            <span className="text-xs font-mono text-muted-foreground">
              optimized_firewall_rules.txt
            </span>
          </div>

          {/* Rules Content */}
          <div className="max-h-96 overflow-y-auto scrollbar-cyber">
            {rules.length > 0 ? (
              <table className="w-full">
                <tbody className="font-mono text-sm">
                  {rules.map((rule, index) => (
                    <tr 
                      key={`opt-${index}`}
                      className="border-b border-border/50 last:border-b-0 hover:bg-muted/20 transition-colors"
                    >
                      {/* Line Number */}
                      <td className="px-4 py-2 text-muted-foreground text-right w-16 select-none border-r border-border/30">
                        {rule.order}
                      </td>
                      
                      {/* Rule Content */}
                      <td className="px-4 py-2 text-foreground whitespace-pre overflow-x-auto">
                        {rule.raw}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="p-8 text-center text-muted-foreground">
                No optimized rules available
              </div>
            )}
          </div>
        </div>

        {/* Usage Instructions */}
        {rules.length > 0 && (
          <div className="mt-4 p-3 bg-muted/30 rounded-lg border border-border/50">
            <p className="text-xs text-muted-foreground">
              <span className="font-medium text-foreground">Usage:</span>{' '}
              Apply these rules with{' '}
              <code className="px-1.5 py-0.5 bg-input rounded text-primary font-mono">
                iptables-restore &lt; optimized_firewall_rules.txt
              </code>
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
