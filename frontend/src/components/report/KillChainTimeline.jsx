import React from "react"

// --------------- Tactic color map ---------------
// Full literal strings only - no dynamic construction.
// Covers both TA00XX format and full name format.
const TACTIC_STYLES = {
  // Initial Access
  TA0001: {
    border: "border-l-red-500",
    node: "bg-red-500",
    glow: "shadow-red-500/20",
    badge: "bg-red-900 text-red-300",
    text: "text-red-400",
  },
  "Initial Access": {
    border: "border-l-red-500",
    node: "bg-red-500",
    glow: "shadow-red-500/20",
    badge: "bg-red-900 text-red-300",
    text: "text-red-400",
  },
  // Execution
  TA0002: {
    border: "border-l-blue-500",
    node: "bg-blue-500",
    glow: "shadow-blue-500/20",
    badge: "bg-blue-900 text-blue-300",
    text: "text-blue-400",
  },
  Execution: {
    border: "border-l-blue-500",
    node: "bg-blue-500",
    glow: "shadow-blue-500/20",
    badge: "bg-blue-900 text-blue-300",
    text: "text-blue-400",
  },
  // Persistence
  TA0003: {
    border: "border-l-purple-500",
    node: "bg-purple-500",
    glow: "shadow-purple-500/20",
    badge: "bg-purple-900 text-purple-300",
    text: "text-purple-400",
  },
  Persistence: {
    border: "border-l-purple-500",
    node: "bg-purple-500",
    glow: "shadow-purple-500/20",
    badge: "bg-purple-900 text-purple-300",
    text: "text-purple-400",
  },
  // Privilege Escalation
  TA0004: {
    border: "border-l-orange-500",
    node: "bg-orange-500",
    glow: "shadow-orange-500/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
  },
  "Privilege Escalation": {
    border: "border-l-orange-500",
    node: "bg-orange-500",
    glow: "shadow-orange-500/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
  },
  // Defense Evasion
  TA0005: {
    border: "border-l-slate-400",
    node: "bg-slate-400",
    glow: "shadow-slate-400/20",
    badge: "bg-slate-800 text-slate-300",
    text: "text-slate-400",
  },
  "Defense Evasion": {
    border: "border-l-slate-400",
    node: "bg-slate-400",
    glow: "shadow-slate-400/20",
    badge: "bg-slate-800 text-slate-300",
    text: "text-slate-400",
  },
  // Credential Access
  TA0006: {
    border: "border-l-amber-500",
    node: "bg-amber-500",
    glow: "shadow-amber-500/20",
    badge: "bg-amber-900 text-amber-300",
    text: "text-amber-400",
  },
  "Credential Access": {
    border: "border-l-amber-500",
    node: "bg-amber-500",
    glow: "shadow-amber-500/20",
    badge: "bg-amber-900 text-amber-300",
    text: "text-amber-400",
  },
  // Discovery
  TA0007: {
    border: "border-l-teal-500",
    node: "bg-teal-500",
    glow: "shadow-teal-500/20",
    badge: "bg-teal-900 text-teal-300",
    text: "text-teal-400",
  },
  Discovery: {
    border: "border-l-teal-500",
    node: "bg-teal-500",
    glow: "shadow-teal-500/20",
    badge: "bg-teal-900 text-teal-300",
    text: "text-teal-400",
  },
  // Lateral Movement
  TA0008: {
    border: "border-l-orange-400",
    node: "bg-orange-400",
    glow: "shadow-orange-400/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
  },
  "Lateral Movement": {
    border: "border-l-orange-400",
    node: "bg-orange-400",
    glow: "shadow-orange-400/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
  },
  // Collection
  TA0009: {
    border: "border-l-cyan-500",
    node: "bg-cyan-500",
    glow: "shadow-cyan-500/20",
    badge: "bg-cyan-900 text-cyan-300",
    text: "text-cyan-400",
  },
  Collection: {
    border: "border-l-cyan-500",
    node: "bg-cyan-500",
    glow: "shadow-cyan-500/20",
    badge: "bg-cyan-900 text-cyan-300",
    text: "text-cyan-400",
  },
  // Exfiltration
  TA0010: {
    border: "border-l-rose-500",
    node: "bg-rose-500",
    glow: "shadow-rose-500/20",
    badge: "bg-rose-900 text-rose-300",
    text: "text-rose-400",
  },
  Exfiltration: {
    border: "border-l-rose-500",
    node: "bg-rose-500",
    glow: "shadow-rose-500/20",
    badge: "bg-rose-900 text-rose-300",
    text: "text-rose-400",
  },
  // Impact
  TA0040: {
    border: "border-l-red-600",
    node: "bg-red-600",
    glow: "shadow-red-600/30",
    badge: "bg-red-900 text-red-200",
    text: "text-red-400",
  },
  Impact: {
    border: "border-l-red-600",
    node: "bg-red-600",
    glow: "shadow-red-600/30",
    badge: "bg-red-900 text-red-200",
    text: "text-red-400",
  },
  // Command and Control
  TA0011: {
    border: "border-l-violet-500",
    node: "bg-violet-500",
    glow: "shadow-violet-500/20",
    badge: "bg-violet-900 text-violet-300",
    text: "text-violet-400",
  },
  "Command and Control": {
    border: "border-l-violet-500",
    node: "bg-violet-500",
    glow: "shadow-violet-500/20",
    badge: "bg-violet-900 text-violet-300",
    text: "text-violet-400",
  },
}

const DEFAULT_TACTIC_STYLE = {
  border: "border-l-blue-500",
  node: "bg-blue-500",
  glow: "shadow-blue-500/20",
  badge: "bg-blue-900 text-blue-300",
  text: "text-blue-400",
}

// --------------- Helpers ---------------

const getTacticStyle = (tactic) => {
  if (!tactic) return DEFAULT_TACTIC_STYLE
  return TACTIC_STYLES[tactic] ?? DEFAULT_TACTIC_STYLE
}

const getTechniqueId = (technique) => {
  if (!technique) return null
  const match = technique.match(/^(T\d{4}(?:\.\d{3})?)/i)
  return match ? match[1].toUpperCase() : null
}

const getTechniqueName = (technique) => {
  if (!technique) return null
  const parts = technique.split(/\s*-\s*/)
  if (parts.length > 1) {
    const name = parts.slice(1).join(" - ").trim()
    return name.length > 35 ? name.slice(0, 35) + "..." : name
  }
  return null
}

const normalizeAssets = (assets) => {
  if (!Array.isArray(assets)) return []
  return assets.filter(
    (asset) =>
      asset && typeof asset === "string" && asset.trim().length > 0
  )
}

const normalizeStages = (stages) => {
  if (!Array.isArray(stages)) return []
  return stages
    .filter((stage) => stage && typeof stage === "object")
    .map((stage, idx) => ({
      number: Number.isFinite(Number(stage.stage_number))
        ? Number(stage.stage_number)
        : idx + 1,
      name: stage.stage_name ?? `Stage ${idx + 1}`,
      tactic: stage.mitre_tactic ?? null,
      technique: stage.mitre_technique ?? null,
      techniqueId: getTechniqueId(stage.mitre_technique),
      techniqueName: getTechniqueName(stage.mitre_technique),
      timestamp: stage.timestamp ?? null,
      evidence: stage.evidence ?? null,
      confidence:
        stage.confidence === "CONFIRMED" ? "CONFIRMED" : "INFERRED",
      assets: normalizeAssets(stage.affected_assets),
      originalIndex: idx,
    }))
    .sort((a, b) => a.number - b.number)
}

const joinClasses = (...classes) => classes.filter(Boolean).join(" ")

// --------------- Main Component ---------------

const KillChainTimeline = ({ stages = [] }) => {
  const normalized = normalizeStages(stages)
  if (normalized.length === 0) return null

  const confirmedCount = normalized.filter(
    (stage) => stage.confidence === "CONFIRMED"
  ).length
  const inferredCount = normalized.length - confirmedCount
  const entryStage = normalized[0]
  const finalStage = normalized[normalized.length - 1]
  const isFinalImpact = finalStage.name
    ?.toLowerCase()
    .match(/impact|encrypt|exfil|compromise|credential/)
  const useScroll = normalized.length > 4

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-4 rounded-sm bg-sentinel-accent" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              Reconstructed Attack Path
            </h3>
          </div>
          <p className="text-xs text-sentinel-muted ml-4">
            {normalized.length} stage
            {normalized.length !== 1 ? "s" : ""}
            {confirmedCount > 0 && (
              <span className="text-green-400">
                {" "}&bull; {confirmedCount} confirmed
              </span>
            )}
            {inferredCount > 0 && (
              <span className="text-amber-400">
                {" "}&bull; {inferredCount} inferred
              </span>
            )}
            <span className="text-sentinel-muted">
              {" "}&bull; MITRE mapped
            </span>
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap ml-4 sm:ml-0">
          {entryStage.techniqueId && (
            <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted">
              Entry{" "}
              <span className="font-mono text-blue-400">
                {entryStage.techniqueId}
              </span>
            </span>
          )}
          {normalized.length > 1 && finalStage.techniqueId && (
            <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted">
              Final{" "}
              <span
                className={
                  isFinalImpact
                    ? "font-mono text-red-400"
                    : "font-mono text-blue-400"
                }
              >
                {finalStage.techniqueId}
              </span>
            </span>
          )}
        </div>
      </div>

      <div className={useScroll ? "overflow-x-auto pb-1" : "overflow-visible"}>
        <div
          className={
            useScroll
              ? "flex items-stretch gap-0 min-w-max"
              : "flex items-stretch gap-0 w-full"
          }
        >
          {normalized.map((stage, idx) => {
            const tacticStyle = getTacticStyle(stage.tactic)
            const isLast = idx === normalized.length - 1
            const isConfirmed = stage.confidence === "CONFIRMED"
            const isImpact = isLast && isFinalImpact
            const cardClasses = joinClasses(
              "flex flex-col gap-2 p-3 rounded-lg",
              "bg-sentinel-bg border border-sentinel-border",
              "border-l-4",
              tacticStyle.border,
              isImpact ? "shadow-lg" : "",
              isImpact ? tacticStyle.glow : "",
              useScroll ? "min-w-[200px] max-w-[240px]" : "flex-1 min-w-0",
              "transition-all duration-200",
              "hover:border-opacity-80 hover:bg-opacity-80"
            )
            const nodeClasses = joinClasses(
              "w-6 h-6 rounded-full flex items-center",
              "justify-center text-xs font-bold text-white shrink-0",
              tacticStyle.node
            )
            const tacticClasses = joinClasses(
              "text-xs font-medium",
              tacticStyle.text
            )
            const techniqueBadgeClasses = joinClasses(
              "text-xs px-1.5 py-0.5 rounded font-mono font-medium",
              tacticStyle.badge
            )

            return (
              <React.Fragment key={stage.originalIndex}>
                <div className={cardClasses} title={stage.evidence ?? ""}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={nodeClasses}>{stage.number}</div>
                      <span className={tacticClasses}>
                        {stage.tactic ?? ""}
                      </span>
                    </div>
                    <span
                      className={
                        isConfirmed
                          ? "text-xs px-1.5 py-0.5 rounded font-medium shrink-0 bg-green-900 text-green-300"
                          : "text-xs px-1.5 py-0.5 rounded font-medium shrink-0 bg-amber-900 text-amber-300"
                      }
                    >
                      {isConfirmed ? "CONFIRMED" : "INFERRED"}
                    </span>
                  </div>

                  <p className="text-sm font-semibold text-white leading-tight">
                    {stage.name}
                    {isImpact && (
                      <span className="ml-1 text-red-400 text-xs">
                        &bull;
                      </span>
                    )}
                  </p>

                  {stage.techniqueId && (
                    <div className="flex items-center gap-1 flex-wrap">
                      <span className={techniqueBadgeClasses}>
                        {stage.techniqueId}
                      </span>
                      {stage.techniqueName && (
                        <span className="text-xs text-sentinel-muted leading-tight">
                          {stage.techniqueName}
                        </span>
                      )}
                    </div>
                  )}

                  {stage.evidence && (
                    <p
                      className="text-xs text-sentinel-muted leading-snug"
                      style={{
                        display: "-webkit-box",
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: "vertical",
                        overflow: "hidden",
                      }}
                    >
                      {stage.evidence}
                    </p>
                  )}

                  <div className="flex items-center justify-between gap-1 mt-auto flex-wrap">
                    {stage.timestamp && stage.timestamp !== "unknown" && (
                      <span className="text-xs text-sentinel-muted font-mono">
                        {stage.timestamp.length > 16
                          ? stage.timestamp.slice(0, 16)
                          : stage.timestamp}
                      </span>
                    )}
                    {stage.assets.length > 0 && (
                      <span
                        className="text-xs px-1.5 py-0.5 rounded bg-sentinel-surface border border-sentinel-border text-sentinel-muted font-mono truncate max-w-[100px]"
                        title={stage.assets[0]}
                      >
                        {stage.assets[0].length > 15
                          ? stage.assets[0].slice(0, 15) + "..."
                          : stage.assets[0]}
                        {stage.assets.length > 1 && (
                          <span> +{stage.assets.length - 1}</span>
                        )}
                      </span>
                    )}
                  </div>
                </div>

                {!isLast && (
                  <div className="flex items-center shrink-0 px-1 self-center">
                    <div className="flex items-center gap-0">
                      <div className="w-4 h-px bg-sentinel-border" />
                      <svg
                        width="8"
                        height="10"
                        viewBox="0 0 8 10"
                        className="text-sentinel-muted shrink-0"
                        fill="currentColor"
                      >
                        <path d="M0 0 L8 5 L0 10 Z" />
                      </svg>
                    </div>
                  </div>
                )}
              </React.Fragment>
            )
          })}
        </div>
      </div>

      {useScroll && (
        <p className="text-xs text-sentinel-muted mt-2 text-right">
          {normalized.length} stages &bull; scroll to view all
        </p>
      )}
    </div>
  )
}

export default KillChainTimeline
