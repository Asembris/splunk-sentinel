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
    ring: "ring-red-500",
    connector: "#ef4444",
  },
  "Initial Access": {
    border: "border-l-red-500",
    node: "bg-red-500",
    glow: "shadow-red-500/20",
    badge: "bg-red-900 text-red-300",
    text: "text-red-400",
    ring: "ring-red-500",
    connector: "#ef4444",
  },
  // Execution
  TA0002: {
    border: "border-l-blue-500",
    node: "bg-blue-500",
    glow: "shadow-blue-500/20",
    badge: "bg-blue-900 text-blue-300",
    text: "text-blue-400",
    ring: "ring-blue-500",
    connector: "#3b82f6",
  },
  Execution: {
    border: "border-l-blue-500",
    node: "bg-blue-500",
    glow: "shadow-blue-500/20",
    badge: "bg-blue-900 text-blue-300",
    text: "text-blue-400",
    ring: "ring-blue-500",
    connector: "#3b82f6",
  },
  // Persistence
  TA0003: {
    border: "border-l-purple-500",
    node: "bg-purple-500",
    glow: "shadow-purple-500/20",
    badge: "bg-purple-900 text-purple-300",
    text: "text-purple-400",
    ring: "ring-purple-500",
    connector: "#a855f7",
  },
  Persistence: {
    border: "border-l-purple-500",
    node: "bg-purple-500",
    glow: "shadow-purple-500/20",
    badge: "bg-purple-900 text-purple-300",
    text: "text-purple-400",
    ring: "ring-purple-500",
    connector: "#a855f7",
  },
  // Privilege Escalation
  TA0004: {
    border: "border-l-orange-500",
    node: "bg-orange-500",
    glow: "shadow-orange-500/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
    ring: "ring-orange-500",
    connector: "#f97316",
  },
  "Privilege Escalation": {
    border: "border-l-orange-500",
    node: "bg-orange-500",
    glow: "shadow-orange-500/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
    ring: "ring-orange-500",
    connector: "#f97316",
  },
  // Defense Evasion
  TA0005: {
    border: "border-l-slate-400",
    node: "bg-slate-400",
    glow: "shadow-slate-400/20",
    badge: "bg-slate-800 text-slate-300",
    text: "text-slate-400",
    ring: "ring-slate-400",
    connector: "#94a3b8",
  },
  "Defense Evasion": {
    border: "border-l-slate-400",
    node: "bg-slate-400",
    glow: "shadow-slate-400/20",
    badge: "bg-slate-800 text-slate-300",
    text: "text-slate-400",
    ring: "ring-slate-400",
    connector: "#94a3b8",
  },
  // Credential Access
  TA0006: {
    border: "border-l-amber-500",
    node: "bg-amber-500",
    glow: "shadow-amber-500/20",
    badge: "bg-amber-900 text-amber-300",
    text: "text-amber-400",
    ring: "ring-amber-500",
    connector: "#f59e0b",
  },
  "Credential Access": {
    border: "border-l-amber-500",
    node: "bg-amber-500",
    glow: "shadow-amber-500/20",
    badge: "bg-amber-900 text-amber-300",
    text: "text-amber-400",
    ring: "ring-amber-500",
    connector: "#f59e0b",
  },
  // Discovery
  TA0007: {
    border: "border-l-teal-500",
    node: "bg-teal-500",
    glow: "shadow-teal-500/20",
    badge: "bg-teal-900 text-teal-300",
    text: "text-teal-400",
    ring: "ring-teal-500",
    connector: "#14b8a6",
  },
  Discovery: {
    border: "border-l-teal-500",
    node: "bg-teal-500",
    glow: "shadow-teal-500/20",
    badge: "bg-teal-900 text-teal-300",
    text: "text-teal-400",
    ring: "ring-teal-500",
    connector: "#14b8a6",
  },
  // Lateral Movement
  TA0008: {
    border: "border-l-orange-400",
    node: "bg-orange-400",
    glow: "shadow-orange-400/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
    ring: "ring-orange-400",
    connector: "#fb923c",
  },
  "Lateral Movement": {
    border: "border-l-orange-400",
    node: "bg-orange-400",
    glow: "shadow-orange-400/20",
    badge: "bg-orange-900 text-orange-300",
    text: "text-orange-400",
    ring: "ring-orange-400",
    connector: "#fb923c",
  },
  // Collection
  TA0009: {
    border: "border-l-cyan-500",
    node: "bg-cyan-500",
    glow: "shadow-cyan-500/20",
    badge: "bg-cyan-900 text-cyan-300",
    text: "text-cyan-400",
    ring: "ring-cyan-500",
    connector: "#06b6d4",
  },
  Collection: {
    border: "border-l-cyan-500",
    node: "bg-cyan-500",
    glow: "shadow-cyan-500/20",
    badge: "bg-cyan-900 text-cyan-300",
    text: "text-cyan-400",
    ring: "ring-cyan-500",
    connector: "#06b6d4",
  },
  // Exfiltration
  TA0010: {
    border: "border-l-rose-500",
    node: "bg-rose-500",
    glow: "shadow-rose-500/20",
    badge: "bg-rose-900 text-rose-300",
    text: "text-rose-400",
    ring: "ring-rose-500",
    connector: "#f43f5e",
  },
  Exfiltration: {
    border: "border-l-rose-500",
    node: "bg-rose-500",
    glow: "shadow-rose-500/20",
    badge: "bg-rose-900 text-rose-300",
    text: "text-rose-400",
    ring: "ring-rose-500",
    connector: "#f43f5e",
  },
  // Impact
  TA0040: {
    border: "border-l-red-600",
    node: "bg-red-600",
    glow: "shadow-red-600/30",
    badge: "bg-red-900 text-red-200",
    text: "text-red-400",
    ring: "ring-red-600",
    connector: "#dc2626",
  },
  Impact: {
    border: "border-l-red-600",
    node: "bg-red-600",
    glow: "shadow-red-600/30",
    badge: "bg-red-900 text-red-200",
    text: "text-red-400",
    ring: "ring-red-600",
    connector: "#dc2626",
  },
  // Command and Control
  TA0011: {
    border: "border-l-violet-500",
    node: "bg-violet-500",
    glow: "shadow-violet-500/20",
    badge: "bg-violet-900 text-violet-300",
    text: "text-violet-400",
    ring: "ring-violet-500",
    connector: "#8b5cf6",
  },
  "Command and Control": {
    border: "border-l-violet-500",
    node: "bg-violet-500",
    glow: "shadow-violet-500/20",
    badge: "bg-violet-900 text-violet-300",
    text: "text-violet-400",
    ring: "ring-violet-500",
    connector: "#8b5cf6",
  },
}

const DEFAULT_TACTIC_STYLE = {
  border: "border-l-blue-500",
  node: "bg-blue-500",
  glow: "shadow-blue-500/20",
  badge: "bg-blue-900 text-blue-300",
  text: "text-blue-400",
  ring: "ring-blue-500",
  connector: "#3b82f6",
}

const ACTIVITY_SUBTITLES_BY_TECHNIQUE = {
  "T1059.003": "Process execution",
  "T1562.004": "Firewall modification",
  "T1552.005": "Credential exposure",
  "T1021.002": "Lateral access",
  T1083: "File discovery",
  T1547: "Persistence mechanism",
  T1078: "Valid account activity",
  T1486: "Encryption impact",
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

const splitTimelineRows = (stages) => {
  if (stages.length <= 5) return [stages]
  return [stages.slice(0, 5), stages.slice(5)]
}

const extractEvidenceHighlight = (evidence) => {
  if (!evidence) return null

  const ipMatch = evidence.match(
    /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/
  )
  const eventCodeMatch = evidence.match(/EventCode\s+(\d{4,5})/i)
  const processMatch = evidence.match(/\b(\w+\.exe)\b/i)
  const uriMatch = evidence.match(/(\/[\w\-./]{8,40})/)
  const credMatch = evidence.match(
    /\b(EC2InstanceRole|AccessKey|SecretKey|IAM\w+)\b/i
  )

  if (ipMatch?.[1]) {
    return {
      label: ipMatch[1] === "169.254.169.254" ? "Meta IP" : "IP",
      value: ipMatch[1],
    }
  }
  if (eventCodeMatch?.[1]) {
    return { label: "EventCode", value: eventCodeMatch[1] }
  }
  if (processMatch?.[1]) {
    return { label: "Process", value: processMatch[1] }
  }
  if (uriMatch?.[1]) {
    return { label: "URI", value: uriMatch[1] }
  }
  if (credMatch?.[1]) {
    return { label: "Credential", value: credMatch[1] }
  }

  return null
}

const normalizeRepeatLabel = (value) =>
  String(value || "").trim().toLowerCase()

const buildRepeatCounts = (stages) => {
  const counts = {
    names: {},
    tactics: {},
    eventCodes: {},
  }

  stages.forEach((stage) => {
    const name = normalizeRepeatLabel(stage.name)
    const tactic = normalizeRepeatLabel(stage.tactic)
    const eventCode = stage.evidence?.match(/EventCode\s+(\d{4,5})/i)?.[1]

    if (name) counts.names[name] = (counts.names[name] || 0) + 1
    if (tactic) counts.tactics[tactic] = (counts.tactics[tactic] || 0) + 1
    if (eventCode) {
      counts.eventCodes[eventCode] = (counts.eventCodes[eventCode] || 0) + 1
    }
  })

  return counts
}

const getStageActivitySubtitle = (stage) => {
  const techniqueId = stage.techniqueId
  if (techniqueId && ACTIVITY_SUBTITLES_BY_TECHNIQUE[techniqueId]) {
    return ACTIVITY_SUBTITLES_BY_TECHNIQUE[techniqueId]
  }

  return null
}

const shouldShowActivitySubtitle = (
  stage,
  activitySubtitle,
  repeatCounts,
  isLongChain
) => {
  if (!isLongChain || !activitySubtitle) return false

  const stageName = String(stage.name || "")
  if (activitySubtitle.toLowerCase() === stageName.toLowerCase()) {
    return false
  }

  const nameKey = normalizeRepeatLabel(stage.name)
  const tacticKey = normalizeRepeatLabel(stage.tactic)
  const eventCode = stage.evidence?.match(/EventCode\s+(\d{4,5})/i)?.[1]

  return (
    (nameKey && repeatCounts.names[nameKey] > 1) ||
    (tacticKey && repeatCounts.tactics[tacticKey] > 1) ||
    (eventCode && repeatCounts.eventCodes[eventCode] > 1)
  )
}

const getConfidenceMeta = (confidence) => {
  if (confidence === "CONFIRMED") {
    return {
      label: "CONF",
      description: "Confirmed by direct telemetry evidence",
    }
  }

  return {
    label: "INF",
    description: "Inferred from attack sequence; no direct telemetry event",
  }
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
  const isLongChain = normalized.length > 5
  const timelineRows = splitTimelineRows(normalized)
  const repeatCounts = buildRepeatCounts(normalized)

  return (
    <div
      className="bg-sentinel-surface border
                 border-sentinel-border rounded-xl p-5"
      style={{
        borderTop: `2px solid ${
          normalized.length > 0
            ? (TACTIC_STYLES[normalized[0]?.tactic]?.connector ??
              "#3b82f6")
            : "#3b82f6"
        }`,
      }}
    >
      {/* Header - two row layout */}
      <div className="flex flex-col gap-2 mb-4">
        {/* Row 1: Title left, chips right */}
        <div className="flex flex-row items-start justify-between gap-3">
          {/* Left: title + subtitle */}
          <div className="min-w-0">
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
            <p className="text-[10px] text-sentinel-muted/80 ml-4 mt-0.5">
              CONF = direct telemetry evidence &middot; INF = inferred from sequence
            </p>
          </div>

          {/* Right: Entry/Final chips */}
          <div className="flex items-center gap-2 flex-wrap shrink-0">
            {entryStage.techniqueId && (
              <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
                Entry{" "}
                <span className="font-mono text-blue-400">
                  {entryStage.techniqueId}
                </span>
              </span>
            )}
            {normalized.length > 1 && finalStage.techniqueId && (
              <span className="text-xs px-2 py-1 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-muted whitespace-nowrap">
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

        {/* Row 2: Full-width story strip */}
        {normalized.length >= 2 && (
          <div className="flex items-center gap-1.5 flex-wrap ml-4 min-w-0">
            <span className="text-xs text-sentinel-muted uppercase tracking-wider font-medium shrink-0">
              Path
            </span>
            <span className="text-xs font-medium text-white">
              {normalized.length}-stage attack chain
            </span>
          </div>
        )}
      </div>

      <div
        className="overflow-visible relative"
      >
        <div className={isLongChain ? "flex flex-col gap-5" : ""}>
          {timelineRows.map((rowStages, rowIdx) => {
            const rowFirstStage = rowStages[0]
            const rowLastStage = rowStages[rowStages.length - 1]
            const rowIsFinalImpact =
              rowIdx === timelineRows.length - 1 && isFinalImpact

            return (
              <div
                key={rowIdx}
                className="flex flex-col gap-3 w-full sm:flex-row sm:items-stretch sm:gap-0 relative"
              >
                {/* Faint telemetry grid */}
                <div
                  className="hidden sm:block absolute inset-0 rounded-lg pointer-events-none"
                  style={{
                    background: `repeating-linear-gradient(
                      90deg,
                      transparent,
                      transparent 59px,
                      rgba(31, 41, 55, 0.4) 59px,
                      rgba(31, 41, 55, 0.4) 60px
                    )`,
                    zIndex: 0,
                  }}
                />

                {/* Continuous attack rail line */}
                <div
                  className="hidden sm:block absolute pointer-events-none"
                  style={{
                    left: "12px",
                    right: "12px",
                    bottom: "18px",
                    height: "2px",
                    background: `linear-gradient(to right, ${
                      rowFirstStage
                        ? (TACTIC_STYLES[rowFirstStage.tactic]?.connector ??
                          DEFAULT_TACTIC_STYLE.connector)
                        : DEFAULT_TACTIC_STYLE.connector
                    }66, ${
                      rowLastStage
                        ? (TACTIC_STYLES[rowLastStage.tactic]?.connector ??
                          DEFAULT_TACTIC_STYLE.connector)
                        : DEFAULT_TACTIC_STYLE.connector
                    }99)`,
                    zIndex: 0,
                  }}
                />

                {/* Final impact radial glow */}
                {rowIsFinalImpact && (
                  <div
                    className="hidden sm:block absolute pointer-events-none"
                    style={{
                      top: 0,
                      right: 0,
                      bottom: 0,
                      width: "30%",
                      background: `radial-gradient(
                        ellipse at 90% 50%,
                        ${
                          finalStage
                            ? (TACTIC_STYLES[finalStage.tactic]?.connector ??
                              "#dc2626")
                            : "#dc2626"
                        }18,
                        transparent 70%
                      )`,
                      zIndex: 0,
                    }}
                  />
                )}

                {rowStages.map((stage, rowStageIdx) => {
            const tacticStyle = getTacticStyle(stage.tactic)
            const idx = normalized.indexOf(stage)
            const isLast = idx === normalized.length - 1
            const isLastInRow = rowStageIdx === rowStages.length - 1
            const isConfirmed = stage.confidence === "CONFIRMED"
            const confidenceMeta = getConfidenceMeta(stage.confidence)
            const isImpact = isLast && isFinalImpact
            const isFinalStage = isLast
            const isDenseCard = isLongChain

            const nodeClasses = joinClasses(
              "w-9 h-9 rounded-full flex items-center",
              "justify-center text-sm font-bold text-white",
              "shrink-0 border-2",
              isImpact ? "border-white/60" : "border-white/20",
              "ring-2 ring-offset-2 ring-offset-sentinel-bg",
              tacticStyle.node,
              tacticStyle.ring ?? "ring-blue-500",
              isImpact
                ? "shadow-xl ring-offset-sentinel-bg animate-pulse brightness-125"
                : ""
            )

            const techniqueBadgeClasses = joinClasses(
              "text-xs px-1.5 py-0.5 rounded",
              "font-mono font-medium",
              tacticStyle.badge
            )

            const highlight = extractEvidenceHighlight(stage.evidence)
            const activitySubtitle = getStageActivitySubtitle(stage)
            const showActivitySubtitle = shouldShowActivitySubtitle(
              stage,
              activitySubtitle,
              repeatCounts,
              isLongChain
            )

            return (
              <React.Fragment key={stage.originalIndex}>
                {/* Stage unit: capsule stem node */}
                <div
                  className="flex flex-col items-center flex-1 min-w-0 relative z-10"
                >
                  {/* Telemetry capsule above rail */}
                  <div
                    className={joinClasses(
                      isDenseCard
                        ? "w-full h-[116px] overflow-hidden p-2 rounded-lg"
                        : "w-full h-[132px] overflow-hidden p-2.5 rounded-lg",
                      "bg-sentinel-bg border border-sentinel-border",
                      "border-l-4 opacity-100",
                      tacticStyle.border,
                      isImpact ? "shadow-lg" : "",
                      isImpact ? tacticStyle.glow : "",
                      isFinalStage && !isImpact
                        ? "border-b-2 border-b-sentinel-accent"
                        : ""
                    )}
                  >
                    {/* Stage number + tactic label */}
                    <div className="flex items-center justify-end mb-1">
                      <span
                        className="flex items-center gap-1"
                        title={confidenceMeta.description}
                        aria-label={confidenceMeta.description}
                      >
                        <span
                          className={
                            isConfirmed
                              ? "w-1.5 h-1.5 rounded-full bg-green-400 shrink-0"
                              : "w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0"
                          }
                        />
                        <span
                          className={
                            isConfirmed
                              ? "text-xs font-medium text-green-400"
                              : "text-xs font-medium text-amber-400"
                          }
                        >
                          {confidenceMeta.label}
                        </span>
                      </span>
                    </div>

                    {/* Stage name - primary label */}
                    <p
                      className={joinClasses(
                        "text-sm font-semibold leading-tight mb-1",
                        isFinalStage ? tacticStyle.text : "text-white"
                      )}
                      style={{
                        display: "-webkit-box",
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: "vertical",
                        overflow: "hidden",
                      }}
                      title={stage.name}
                    >
                      {stage.name}
                      {isImpact && (
                        <span className="ml-1 text-red-400">
                          &bull;
                        </span>
                      )}
                    </p>
                    {showActivitySubtitle && (
                      <p
                        className="text-[10px] leading-tight text-sentinel-muted mb-1 truncate"
                        title={activitySubtitle}
                      >
                        {activitySubtitle}
                      </p>
                    )}

                    {/* Technique badge */}
                    {stage.techniqueId && (
                      <span
                        className={techniqueBadgeClasses}
                        title={stage.technique ?? ""}
                      >
                        {stage.techniqueId}
                      </span>
                    )}

                    {/* Forensic highlight chip */}
                    {highlight && (
                      <div className="mt-1 min-w-0">
                        <span
                          className="text-[10px] px-1 py-0.5 rounded font-mono bg-sentinel-surface border border-sentinel-border text-blue-300 block truncate"
                          title={`${highlight.label}: ${highlight.value}`}
                        >
                          <span className="text-sentinel-muted">
                            {highlight.label}:{" "}
                          </span>
                          {highlight.value}
                        </span>
                      </div>
                    )}

                    {/* Timestamp - compact */}
                    {!isDenseCard &&
                      stage.timestamp &&
                      stage.timestamp !== "unknown" && (
                      <p
                        className="text-xs text-sentinel-muted font-mono mt-1 opacity-75"
                        title={stage.timestamp}
                      >
                        {stage.timestamp.length > 16
                          ? stage.timestamp.slice(0, 16)
                          : stage.timestamp}
                      </p>
                    )}
                  </div>

                  {/* Vertical telemetry stem */}
                  <div
                    className="shrink-0"
                    style={{
                      width: "2px",
                      height: "12px",
                      background: tacticStyle.connector ?? "#3b82f6",
                      opacity: 0.8,
                      borderRadius: "1px",
                    }}
                  />

                  {/* Node circle on the rail */}
                  <div className={nodeClasses} title={stage.name}>
                    {stage.number}
                  </div>

                  {isImpact && (
                    <span
                      className={joinClasses(
                        "mt-1 text-xs font-bold tracking-wider",
                        tacticStyle.text
                      )}
                    >
                      IMPACT
                    </span>
                  )}
                </div>

                {!isLastInRow && (
                  <div className="hidden sm:block shrink-0 w-1 relative z-10" />
                )}
              </React.Fragment>
            )
                })}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

export default KillChainTimeline
