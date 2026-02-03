import { useState, useRef, ChangeEvent } from 'react';
import { Upload, FileText, AlertCircle, Shield } from 'lucide-react';

interface RuleInputProps {
  onAnalyze: (rules: string) => void;
  isLoading: boolean;
}

/**
 * RuleInput Component
 * 
 * Provides a textarea for pasting firewall rules and file upload capability.
 * Validates input before submission and shows appropriate feedback.
 */
export function RuleInput({ onAnalyze, isLoading }: RuleInputProps) {
  const [rules, setRules] = useState('');
  const [error, setError] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Placeholder text showing expected format
  const placeholderText = `# Paste your iptables rules here (iptables-save format)
# Example:
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
COMMIT`;

  /**
   * Handles file upload and reads content into textarea
   */
  const handleFileUpload = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.name.endsWith('.txt') && !file.type.includes('text')) {
      setError('Please upload a .txt file');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setRules(content);
      setError('');
    };
    reader.onerror = () => {
      setError('Failed to read file');
    };
    reader.readAsText(file);

    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  /**
   * Validates and submits rules for analysis
   */
  const handleSubmit = () => {
    // Validate input
    if (!rules.trim()) {
      setError('Please enter firewall rules to analyze');
      return;
    }

    setError('');
    onAnalyze(rules);
  };

  /**
   * Triggers hidden file input
   */
  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <div className="cyber-card p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <FileText className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h2 className="section-title">Firewall Rules Input</h2>
            <p className="section-subtitle">
              Paste your iptables rules or upload a configuration file
            </p>
          </div>
        </div>
        
        {/* File Upload Button */}
        <button
          onClick={handleUploadClick}
          className="btn-secondary"
          disabled={isLoading}
        >
          <Upload className="w-4 h-4" />
          Upload File
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".txt,text/plain"
          onChange={handleFileUpload}
          className="hidden"
        />
      </div>

      {/* Textarea */}
      <div className="relative">
        <textarea
          value={rules}
          onChange={(e) => {
            setRules(e.target.value);
            if (error) setError('');
          }}
          placeholder={placeholderText}
          className="cyber-input w-full h-64 p-4 font-mono text-sm resize-y scrollbar-cyber"
          disabled={isLoading}
        />
        
        {/* Line count indicator */}
        <div className="absolute bottom-3 right-3 text-xs text-muted-foreground">
          {rules.split('\n').filter(line => line.trim()).length} lines
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="flex items-center gap-2 text-destructive text-sm bg-destructive/10 p-3 rounded-md">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Submit Button */}
      <button
        onClick={handleSubmit}
        disabled={isLoading}
        className="btn-primary w-full"
      >
        {isLoading ? (
          <>
            <div className="loading-spinner" />
            Analyzing Rules...
          </>
        ) : (
          <>
            <Shield className="w-5 h-5" />
            Analyze Rules
          </>
        )}
      </button>
    </div>
  );
}
