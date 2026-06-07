"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { supabase } from "@/lib/supabase";

const PAGE_SIZE = 24;

interface Threat {
  id: string;
  title: string;
  description: string;
  source: string;
  severity: string;
  published_date: string;
  url: string;
  risk_score: number | null;
  risk_label: string | null;
  ai_summary: string | null;
  attack_type: string | null;
  affected_systems: string | null;
  action_required: string | null;
  india_relevance: string | null;
  ai_scored_at: string | null;
  created_at: string;
}

const severityColors: Record<string, string> = {
  CRITICAL: "#ff3366",
  HIGH: "#ff6b35",
  MEDIUM: "#ffd60a",
  LOW: "#06d6a0",
};

const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

function formatDate(iso: string) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function AnimatedCounter({ value, color }: { value: number; color: string }) {
  const [display, setDisplay] = useState(0);
  const startRef = useRef<number | null>(null);

  useEffect(() => {
    startRef.current = null;
    const duration = 800;
    const from = 0;
    const step = (timestamp: number) => {
      if (startRef.current === null) startRef.current = timestamp;
      const elapsed = timestamp - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      setDisplay(Math.floor(from + (value - from) * progress));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [value]);

  return (
    <span className="text-3xl font-bold tabular-nums count-animate" style={{ color }}>
      {display.toLocaleString()}
    </span>
  );
}

function SkeletonCard() {
  return (
    <div className="rounded-xl border border-white/5 bg-white/[0.02] p-5 animate-pulse">
      <div className="flex justify-between mb-3">
        <div className="h-5 w-16 bg-white/5 rounded" />
        <div className="h-5 w-20 bg-white/5 rounded" />
      </div>
      <div className="h-4 bg-white/5 rounded w-3/4 mb-2" />
      <div className="h-4 bg-white/5 rounded w-full mb-1" />
      <div className="h-4 bg-white/5 rounded w-5/6 mb-4" />
      <div className="h-2 bg-white/5 rounded w-1/3 mb-3" />
      <div className="h-3 bg-white/5 rounded w-1/4" />
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = severityColors[severity] || "#888";
  return (
    <span
      className="text-xs font-semibold px-2.5 py-1 rounded-md"
      style={{
        backgroundColor: `${color}18`,
        color,
        border: `1px solid ${color}40`,
      }}
    >
      {severity}
    </span>
  );
}

function SourceBadge({ source }: { source: string }) {
  return (
    <span className="text-xs text-white/50 bg-white/5 px-2.5 py-1 rounded-md border border-white/5">
      {source}
    </span>
  );
}

function RiskBar({ score }: { score: number }) {
  const pct = (score / 10) * 100;
  const color =
    score >= 8 ? "#ff3366" : score >= 6 ? "#ff6b35" : score >= 4 ? "#ffd60a" : "#06d6a0";
  return (
    <div className="flex items-center gap-2 mt-2">
      <span className="text-xs text-white/40 w-16">Risk {score}/10</span>
      <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden relative">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${color}88, ${color})`,
            boxShadow: `0 0 8px ${color}40`,
          }}
        />
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color?: string }) {
  const c = color || "var(--accent)";
  return (
    <div className="group rounded-xl backdrop-blur-sm p-4 flex flex-col items-center transition-all duration-300 relative overflow-hidden"
      style={{
        background: "rgba(0, 212, 255, 0.05)",
        border: "1px solid rgba(0, 212, 255, 0.15)",
      }}
    >
      <div
        className="absolute inset-x-0 top-0 h-0.5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: `linear-gradient(90deg, transparent, ${c}, transparent)`,
          boxShadow: `0 0 8px ${c}60`,
        }}
      />
      <AnimatedCounter value={value} color={c} />
      <span className="text-xs text-white/50 mt-1">{label}</span>
    </div>
  );
}

function RiskBadge({ score }: { score: number }) {
  const color = score >= 8 ? "#ff3366" : score >= 6 ? "#ff6b35" : score >= 4 ? "#ffd60a" : "#06d6a0";
  return (
    <span
      className="text-[11px] font-semibold px-2.5 py-1 rounded-md"
      style={{
        background: `${color}18`,
        color,
        border: `1px solid ${color}40`,
      }}
    >
      Risk {score}/10
    </span>
  );
}

function ThreatModal({ threat, onClose }: { threat: Threat; onClose: () => void }) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [onClose]);

  const sevColor = severityColors[threat.severity] || "#888";
  const isCve = /CVE-\d{4}-\d{4,}/i.test(threat.title);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.8)", backdropFilter: "blur(8px)" }}
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-[600px] rounded-2xl overflow-y-auto max-h-[90vh] p-6 sm:p-8"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "rgba(10,10,20,0.95)",
          border: "1px solid rgba(0,212,255,0.2)",
          borderRadius: "16px",
          boxShadow: "0 0 40px rgba(0,212,255,0.1)",
        }}
      >
        <button
          onClick={onClose}
          className="absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-lg transition-colors text-white/30 hover:text-white/70 hover:bg-white/5"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </button>

        <div className="flex items-center gap-2.5 mb-4 flex-wrap">
          <SeverityBadge severity={threat.severity} />
          <SourceBadge source={threat.source} />
          {threat.risk_score != null && <RiskBadge score={threat.risk_score} />}
        </div>

        <h2 className="text-lg font-bold text-white/95 leading-snug mb-4 flex items-center gap-2">
          {isCve && (
            <span className="text-[#00d4ff]/70 shrink-0">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
          )}
          {threat.title}
        </h2>

        {threat.ai_scored_at && threat.ai_summary ? (
          <div
            className="rounded-xl p-5 mb-4 space-y-4"
            style={{
              background: "rgba(0, 212, 255, 0.06)",
              border: "1px solid rgba(0, 212, 255, 0.2)",
              borderLeft: "3px solid #00d4ff",
            }}
          >
            <span className="text-xs font-semibold text-[#00d4ff] tracking-wider uppercase">AI Analysis</span>

            <p className="text-sm text-white/85 leading-relaxed">{threat.ai_summary}</p>

            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-white/40">Risk Score</span>
                <span className="text-xl font-bold" style={{ color: sevColor }}>
                  {threat.risk_score ?? "—"}
                  <span className="text-sm text-white/30 font-normal">/10</span>
                </span>
              </div>
              {threat.risk_score != null && (
                <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${(threat.risk_score / 10) * 100}%`,
                      background: `linear-gradient(90deg, ${sevColor}88, ${sevColor})`,
                      boxShadow: `0 0 8px ${sevColor}40`,
                    }}
                  />
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3">
              {threat.attack_type && (
                <div>
                  <span className="text-[10px] text-white/40 block mb-0.5">Attack Type</span>
                  <span className="text-xs text-white/70">{threat.attack_type}</span>
                </div>
              )}
              {threat.affected_systems && (
                <div>
                  <span className="text-[10px] text-white/40 block mb-0.5">Affected Systems</span>
                  <span className="text-xs text-white/70">{threat.affected_systems}</span>
                </div>
              )}
            </div>

            {threat.action_required && (
              <span
                className="inline-block text-xs font-medium px-3 py-1.5 rounded-full"
                style={{
                  background: "rgba(255, 214, 10, 0.15)",
                  border: "1px solid rgba(255, 214, 10, 0.3)",
                  color: "#ffd60a",
                }}
              >
                Action Required: {threat.action_required}
              </span>
            )}

            {threat.india_relevance === "High" && (
              <span className="inline-block text-xs text-[#ffd60a] bg-[#ffd60a]/10 px-2.5 py-1 rounded font-medium">
                🇮🇳 India Relevance: High
              </span>
            )}

            {threat.description && (
              <details className="text-xs text-white/40 group cursor-pointer">
                <summary className="hover:text-white/60 transition-colors">
                  Technical Details ▼
                </summary>
                <p className="mt-2 text-xs text-white/50 leading-relaxed whitespace-pre-wrap">
                  {threat.description}
                </p>
              </details>
            )}
          </div>
        ) : (
          <div
            className="rounded-xl p-6 mb-4 flex flex-col items-center text-center"
            style={{
              background: "rgba(255,255,255,0.02)",
              border: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.25)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mb-3">
              <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
            </svg>
            <span className="text-sm font-semibold text-white/50 mb-1">AI Analysis Pending</span>
            <p className="text-xs text-white/30 max-w-xs">
              Our system analyzes Critical and High severity threats automatically. Check back in a few hours for a plain-language summary.
            </p>

            {threat.description && (
              <details className="w-full mt-4 text-xs text-white/40 group cursor-pointer text-left">
                <summary className="hover:text-white/60 transition-colors">
                  Raw Technical Data ▼
                </summary>
                <p className="mt-2 text-xs text-white/50 leading-relaxed whitespace-pre-wrap">
                  {threat.description}
                </p>
              </details>
            )}
          </div>
        )}

        <div className="text-xs text-white/30 mb-6">
          Published: {threat.published_date ? formatDate(threat.published_date) : "Unknown"}
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onClose}
            className="px-5 py-2.5 text-sm rounded-lg transition-all duration-200 text-white/50 border border-white/10 hover:text-white/70 hover:border-white/20"
            style={{ background: "rgba(255,255,255,0.04)" }}
          >
            Close
          </button>
          <a
            href={threat.url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex-1 px-5 py-2.5 text-sm rounded-lg text-center font-medium transition-all duration-200"
            style={{
              background: "linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,212,255,0.1))",
              color: "#00d4ff",
              border: "1px solid rgba(0,212,255,0.3)",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = "linear-gradient(135deg, rgba(0,212,255,0.3), rgba(0,212,255,0.15))"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "linear-gradient(135deg, rgba(0,212,255,0.2), rgba(0,212,255,0.1))"; }}
          >
            View Original Source →
          </a>
        </div>
      </div>
    </div>
  );
}

function ThreatCard({ threat, onSelect }: { threat: Threat; onSelect: (t: Threat) => void }) {
  const summary =
    threat.ai_summary || (threat.description ? threat.description.slice(0, 200) + "..." : "");
  const sevColor = severityColors[threat.severity] || "#888";
  const isCritical = threat.severity === "CRITICAL";
  const isCve = /CVE-\d{4}-\d{4,}/i.test(threat.title);

  return (
    <div
      onClick={() => onSelect(threat)}
      className="card-enter group rounded-xl backdrop-blur-sm p-5 transition-all duration-300 hover:-translate-y-1 relative overflow-hidden cursor-pointer"
      style={{
        background: "rgba(255, 255, 255, 0.02)",
        border: `1px solid rgba(255, 255, 255, 0.06)`,
        borderLeft: `4px solid ${sevColor}`,
        boxShadow: isCritical ? "0 0 20px rgba(255,51,102,0.1)" : "none",
      }}
    >
      <div className="flex items-start justify-between mb-3 gap-2">
        <SeverityBadge severity={threat.severity} />
        <div className="flex items-center gap-2">
          {threat.ai_scored_at && (
            <span
              className="text-[10px] text-[#00d4ff] px-2 py-0.5 rounded font-medium"
              style={{
                background: "rgba(0, 212, 255, 0.12)",
                boxShadow: "0 0 12px rgba(0, 212, 255, 0.25)",
              }}
            >
              AI Analyzed
            </span>
          )}
          <SourceBadge source={threat.source} />
        </div>
      </div>

      <h3 className="text-sm font-semibold text-white/90 leading-snug line-clamp-2 mb-2 group-hover:text-[#00d4ff] transition-colors flex items-center gap-1.5">
        {isCve && (
          <span className="text-[#00d4ff]/70 shrink-0" style={{ fontSize: "0.75rem" }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </span>
        )}
        {threat.title}
      </h3>

      {summary && (
        <p className="text-xs text-white/50 leading-relaxed line-clamp-3 mb-3">
          {summary}
        </p>
      )}

      {threat.risk_score != null && <RiskBar score={threat.risk_score} />}

      <div className="flex items-center gap-2 mt-3 flex-wrap">
        {threat.attack_type && (
          <span className="text-[10px] text-white/40 bg-white/5 px-2 py-0.5 rounded border border-white/5">
            {threat.attack_type}
          </span>
        )}
        {threat.india_relevance === "High" && (
          <span className="text-[10px] text-[#ffd60a] bg-[#ffd60a]/10 px-2 py-0.5 rounded font-medium">
            India
          </span>
        )}
      </div>

      <div className="flex items-center justify-between mt-4 pt-3 border-t border-white/5">
        <span className="text-[11px] text-white/30">
          {threat.published_date ? formatDate(threat.published_date) : ""}
        </span>
        <span className="text-[10px] text-white/20 group-hover:text-white/40 transition-colors">
          Click to expand
        </span>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const fetchThreats = useCallback(async () => {
    try {
      let query = supabase
        .from("threats")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(500);

      const { data, error } = await query;
      if (error) throw error;
      setThreats(data || []);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Failed to fetch threats:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 300000);
    return () => clearInterval(interval);
  }, [fetchThreats]);

  const filtered = threats.filter((t) => {
    if (severityFilter && t.severity !== severityFilter) return false;
    if (sourceFilter && t.source !== sourceFilter) return false;
    return true;
  });

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [severityFilter, sourceFilter]);

  const totalThreats = threats.length;
  const aiScored = threats.filter((t) => t.ai_scored_at).length;
  const criticalToday = threats.filter(
    (t) =>
      t.severity === "CRITICAL" &&
      t.created_at &&
      Date.now() - new Date(t.created_at).getTime() < 86400000
  ).length;

  const sources = [...new Set(threats.map((t) => t.source).filter(Boolean))].sort();
  const hasCritical = criticalToday > 0;

  const severityFilters = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  return (
    <div className="min-h-screen flex flex-col relative">
      <div className="fixed top-0 left-0 right-0 h-0.5 z-50 animate-gradient" />

      <div
        className="fixed top-[-200px] left-[-200px] w-[600px] h-[600px] pointer-events-none z-0"
        style={{
          background: "radial-gradient(circle, rgba(0, 212, 255, 0.12), transparent 70%)",
          filter: "blur(64px)",
        }}
      />

      <div className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6 relative z-10">
        {hasCritical && (
          <div
            className="mb-6 rounded-xl px-5 py-3 flex items-center gap-3 relative overflow-hidden"
            style={{
              background: "rgba(255, 51, 102, 0.1)",
              border: "1px solid rgba(255, 51, 102, 0.3)",
            }}
          >
            <div
              className="absolute bottom-0 left-0 right-0 h-0.5"
              style={{
                background: "linear-gradient(90deg, transparent, #ff3366, #ff336688, transparent)",
                backgroundSize: "200% 100%",
                animation: "gradient-slide 2s ease infinite",
              }}
            />
            <span className="text-lg banner-pulse">&#9888;</span>
            <span className="text-sm font-medium text-[#ff3366]">
              {criticalToday} Critical threat{criticalToday > 1 ? "s" : ""} detected in the last 24
              hours
            </span>
          </div>
        )}

        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <span className="text-2xl">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
            <div>
              <h1 className="text-3xl font-bold tracking-[0.15em] text-[#00d4ff]">CORTEX</h1>
              <p className="text-xs text-white/40 -mt-0.5">Threat Intelligence Platform</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#06d6a0] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#06d6a0]" />
            </span>
            <span className="text-[10px] font-semibold text-[#06d6a0] tracking-widest">LIVE</span>
            <span className="text-[10px] text-white/30 ml-1">
              Updated {timeAgo(lastUpdated.toISOString())}
            </span>
          </div>
        </div>

        <div
          className="mt-4 mb-6"
          style={{
            height: "1px",
            background: "linear-gradient(90deg, transparent, rgba(0, 212, 255, 0.3), transparent)",
            boxShadow: "0 0 6px rgba(0, 212, 255, 0.2)",
          }}
        />

        <div className="grid grid-cols-3 gap-3 mt-2 mb-8">
          <StatCard label="Total Threats" value={totalThreats} color="#00d4ff" />
          <StatCard label="AI Scored" value={aiScored} color="#06d6a0" />
          <StatCard label="Critical Today" value={criticalToday} color="#ff3366" />
        </div>

        <div className="flex flex-wrap items-center gap-2 mb-6 pb-4 border-b border-white/5">
          <button
            onClick={() => setSeverityFilter(null)}
            className={`text-xs px-3 py-1.5 rounded-md transition-all duration-200 ${
              !severityFilter
                ? "bg-[#00d4ff]/15 text-[#00d4ff] border border-[#00d4ff]/30"
                : "text-white/50 bg-white/5 border border-white/5 hover:bg-white/10"
            }`}
            style={
              !severityFilter
                ? { boxShadow: "0 0 12px rgba(0, 212, 255, 0.4)" }
                : {}
            }
          >
            All
          </button>
          {severityFilters.map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`text-xs px-3 py-1.5 rounded-md transition-all duration-200 ${
                severityFilter === s
                  ? "bg-[#00d4ff]/15 text-[#00d4ff] border border-[#00d4ff]/30"
                  : "text-white/50 bg-white/5 border border-white/5 hover:bg-white/10"
              }`}
              style={
                severityFilter === s
                  ? { boxShadow: "0 0 12px rgba(0, 212, 255, 0.4)" }
                  : {}
              }
            >
              {s}
            </button>
          ))}
          <div className="w-px h-5 bg-white/10 mx-1" />
          <select
            value={sourceFilter || ""}
            onChange={(e) => setSourceFilter(e.target.value || null)}
            className="text-xs bg-white/5 border border-white/5 text-white/50 rounded-md px-2.5 py-1.5 outline-none focus:border-[#00d4ff]/30 focus:text-white/70 transition-colors"
          >
            <option value="">All Sources</option>
            {sources.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>

        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : paginated.length === 0 ? (
          <div className="text-center py-20">
            <p className="text-white/30 text-sm">No threats found matching the current filters.</p>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {paginated.map((t, i) => (
                <div key={t.id} style={{ animationDelay: `${(i % PAGE_SIZE) * 30}ms` }}>
                  <ThreatCard threat={t} onSelect={setSelectedThreat} />
                </div>
              ))}
            </div>

            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-4 mt-8 pb-4">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="text-xs px-4 py-2 rounded-md bg-white/5 border border-white/5 text-white/50 hover:bg-white/10 hover:text-white/70 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  ← Previous
                </button>
                <span className="text-xs text-white/40">
                  Page {page} of {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="text-xs px-4 py-2 rounded-md bg-white/5 border border-white/5 text-white/50 hover:bg-white/10 hover:text-white/70 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  Next →
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {selectedThreat && (
        <ThreatModal threat={selectedThreat} onClose={() => setSelectedThreat(null)} />
      )}

      <footer className="border-t border-white/5 py-6 relative z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="text-xs text-white/30">Powered by</span>
            <span className="text-xs font-semibold text-[#00d4ff]">CORTEX</span>
            <span className="text-xs text-white/30">Threat Intelligence</span>
          </div>
          <div className="flex items-center gap-4 text-[10px] text-white/20">
            <span>NVD</span>
            <span>CISA_KEV</span>
            <span>TheHackerNews</span>
            <span>CERT-In</span>
            <span>AlienVault_OTX</span>
          </div>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[10px] text-white/20 hover:text-white/40 transition-colors"
          >
            GitHub →
          </a>
        </div>
      </footer>
    </div>
  );
}
