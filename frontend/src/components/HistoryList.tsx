
import { Clock, CheckCircle, AlertTriangle, Copy, Trash2 } from 'lucide-react';
import type { AnalysisSession } from '../services/api';

interface HistoryListProps {
    history: AnalysisSession[];
    isLoading: boolean;
    onSelectSession?: (sessionId: string) => void;
}

/**
 * HistoryList Component
 * 
 * Displays a list of past analysis sessions.
 */
export function HistoryList({ history, isLoading, onSelectSession }: HistoryListProps) {
    if (isLoading) {
        return (
            <div className="cyber-card p-6 text-center text-muted-foreground">
                <div className="loading-spinner mb-2 mx-auto" />
                Loading history...
            </div>
        );
    }

    if (history.length === 0) {
        return (
            <div className="cyber-card p-6 text-center text-muted-foreground text-sm">
                No analysis history found. Run an analysis to see it here.
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-secondary/50 rounded-lg">
                    <Clock className="w-5 h-5 text-secondary-foreground" />
                </div>
                <div>
                    <h2 className="section-title">Analysis History</h2>
                    <p className="section-subtitle">
                        Recent analysis sessions
                    </p>
                </div>
            </div>

            <div className="grid gap-3 max-h-[500px] overflow-y-auto scrollbar-cyber pr-2">
                {history.map((session) => (
                    <div
                        key={session.id}
                        className="cyber-card p-4 hover:border-primary/50 transition-colors cursor-pointer group"
                        onClick={() => onSelectSession?.(session.id)}
                    >
                        {/* Header */}
                        <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.5 text-xs font-bold rounded uppercase ${session.rule_type === 'nftables'
                                        ? 'bg-purple-500/20 text-purple-400'
                                        : 'bg-blue-500/20 text-blue-400'
                                    }`}>
                                    {session.rule_type}
                                </span>
                                <span className="text-xs text-muted-foreground font-mono">
                                    {new Date(session.created_at).toLocaleString()}
                                </span>
                            </div>
                        </div>

                        {/* Stats Grid */}
                        <div className="grid grid-cols-4 gap-2 text-center">
                            <div className="bg-muted/30 rounded p-1">
                                <div className="text-xs text-muted-foreground">Rules</div>
                                <div className="font-mono font-bold">{session.total_rules}</div>
                            </div>
                            <div className="bg-warning/10 rounded p-1">
                                <div className="text-xs text-warning">Redundant</div>
                                <div className="font-mono font-bold text-warning">{session.redundant_count}</div>
                            </div>
                            <div className="bg-muted-foreground/10 rounded p-1">
                                <div className="text-xs text-muted-foreground">Shadowed</div>
                                <div className="font-mono font-bold text-muted-foreground">{session.shadowed_count}</div>
                            </div>
                            <div className="bg-destructive/10 rounded p-1">
                                <div className="text-xs text-destructive">Conflicts</div>
                                <div className="font-mono font-bold text-destructive">{session.conflict_count}</div>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}
