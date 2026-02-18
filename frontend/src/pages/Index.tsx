import { useState } from 'react';
import { Shield, AlertCircle, Wifi } from 'lucide-react';
import { RuleInput } from '../components/RuleInput';
import { MetricsDisplay } from '../components/MetricsDisplay';
import { AnomalyTables } from '../components/AnomalyTables';
import { OptimizedRules } from '../components/OptimizedRules';
import { analyzeRules, AnalysisResponse } from '../services/api';

/**
 * Main Dashboard Page
 * 
 * The primary interface for the Firewall Rule Analysis and Optimization System.
 * Handles the analysis workflow and displays results.
 */
const Index = () => {
  // State for analysis results
  const [analysisResult, setAnalysisResult] = useState<AnalysisResponse | null>(null);

  // Loading and error states
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Handles the rule analysis process
   * Sends rules to backend API and processes response
   */
  const handleAnalyze = async (rules: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await analyzeRules(rules);
      setAnalysisResult(result);
    } catch (err) {
      const errorMessage = err instanceof Error
        ? err.message
        : 'An unexpected error occurred';
      setError(errorMessage);
      setAnalysisResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center gap-4">
            {/* Logo */}
            <div className="p-2.5 bg-primary/10 rounded-xl">
              <Shield className="w-7 h-7 text-primary" />
            </div>

            {/* Title */}
            <div>
              <h1 className="text-2xl font-bold text-gradient-cyber">
                Firewall Rule Analyzer & Optimizer
              </h1>
              <p className="text-sm text-muted-foreground">
                Analyze, detect anomalies, and optimize your iptables or nftables firewall rules
              </p>
            </div>

            {/* Status Indicator */}
            <div className="ml-auto flex items-center gap-2 text-sm">
              <Wifi className="w-4 h-4 text-muted-foreground" />
              <span className="text-muted-foreground">API:</span>
              <span className="text-primary font-mono text-xs">
                127.0.0.1:8000
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8 space-y-8">
        {/* Rule Input Section */}
        <section>
          <RuleInput onAnalyze={handleAnalyze} isLoading={isLoading} />
        </section>

        {/* Error Display */}
        {error && (
          <div className="cyber-card border-destructive/50 bg-destructive/5 p-4">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="font-medium text-destructive">Analysis Error</h3>
                <p className="text-sm text-muted-foreground mt-1">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Analysis Results */}
        {analysisResult && (
          <>
            {/* Metrics Section */}
            <section>
              <MetricsDisplay metrics={analysisResult.metrics} />
            </section>

            {/* Anomaly Analysis Section */}
            <section>
              <AnomalyTables
                redundantRules={analysisResult.redundant_rules}
                shadowedRules={analysisResult.shadowed_rules}
                conflicts={analysisResult.conflicts}
              />
            </section>

            {/* Optimized Rules Section */}
            <section>
              <OptimizedRules rules={analysisResult.optimized_rules} />
            </section>
          </>
        )}

        {/* Empty State - No Analysis Yet */}
        {!analysisResult && !error && !isLoading && (
          <div className="cyber-card p-12 text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-muted rounded-full mb-4">
              <Shield className="w-8 h-8 text-muted-foreground" />
            </div>
            <h3 className="text-lg font-medium text-foreground mb-2">
              Ready to Analyze
            </h3>
            <p className="text-muted-foreground max-w-md mx-auto">
              Paste your iptables or nftables firewall rules above or upload a configuration file to begin analysis.
              The system will detect anomalies and generate an optimized ruleset.
            </p>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-border mt-auto">
        <div className="container mx-auto px-6 py-4">
          <p className="text-center text-sm text-muted-foreground">
            Firewall Rule Analysis and Optimization System •
            Built for Linux iptables & nftables administration
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
