/**
 * API Service for Firewall Rule Analysis
 * 
 * This module handles all communication with the backend API.
 * The backend expects firewall rules in iptables-save format.
 */

// Backend API endpoint
const API_BASE_URL = 'http://127.0.0.1:8000';

// Types for the API response
export interface RuleMetrics {
  total_rules: number;
  redundant_count: number;
  shadowed_count: number;
  conflict_count: number;
  optimized_count: number;
  reduction_ratio: number;
}

export interface FirewallRule {
  order: number;
  chain: string;
  action: string;
  raw: string;
}

export interface RuleConflict {
  rule1: FirewallRule;
  rule2: FirewallRule;
  reason?: string;
}

export interface AnalysisResponse {
  metrics: RuleMetrics;
  redundant_rules: FirewallRule[];
  shadowed_rules: FirewallRule[];
  conflicts: RuleConflict[];
  optimized_rules: FirewallRule[];
}

export interface ApiError {
  message: string;
  status?: number;
}

/**
 * Analyzes firewall rules by sending them to the backend API
 * 
 * @param rules - Raw firewall rules in iptables-save format
 * @returns Promise containing the analysis results
 * @throws Error if the API request fails
 */
export async function analyzeRules(rules: string): Promise<AnalysisResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ rules }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `API Error (${response.status}): ${errorText || 'Unknown error occurred'}`
      );
    }

    const data: AnalysisResponse = await response.json();
    return data;
  } catch (error) {
    // Handle network errors
    if (error instanceof TypeError && error.message.includes('fetch')) {
      throw new Error(
        'Unable to connect to the backend server. Please ensure the API is running at http://127.0.0.1:8000'
      );
    }
    throw error;
  }
}

/**
 * Generates a downloadable text file from optimized rules
 * 
 * @param rules - Array of optimized firewall rules
 * @returns Blob containing the rules file
 */
export function generateRulesFile(rules: FirewallRule[]): Blob {
  const content = rules.map(rule => rule.raw).join('\n');
  return new Blob([content], { type: 'text/plain' });
}

/**
 * Triggers download of the optimized rules file
 * 
 * @param rules - Array of optimized firewall rules
 * @param filename - Name for the downloaded file
 */
export function downloadRulesFile(rules: FirewallRule[], filename: string = 'optimized_rules.txt'): void {
  const blob = generateRulesFile(rules);
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
