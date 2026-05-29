import React from "react"

const KillChainTimeline = ({ stages = [] }) => {
    if (!stages || stages.length === 0) return null

    const sorted = [...stages].sort((a, b) => {
        const na = a.stage_number ?? 999
        const nb = b.stage_number ?? 999
        return na - nb
    })

    const getTechniqueId = (technique) => {
        if (!technique) return null
        return technique.split(/[\s-]/)[0].trim()
    }

    const truncate = (str, max = 80) => {
        if (!str) return ""
        return str.length > max
            ? str.slice(0, max) + "..."
            : str
    }

    return (
        <div className="bg-sentinel-surface border
                        border-sentinel-border rounded-lg
                        p-4 mb-2">
            <div className="flex items-center gap-2 mb-3">
                <div className="w-2 h-2 rounded-full
                                bg-blue-500" />
                <h3 className="text-xs font-semibold
                               text-sentinel-muted
                               uppercase tracking-wider">
                    Attack Kill Chain
                </h3>
                <span className="text-xs text-sentinel-muted">
                    {sorted.length} stage{sorted.length !== 1
                        ? "s" : ""} confirmed
                </span>
            </div>

            <div className="overflow-x-auto pb-2">
                <div className="flex items-start gap-2"
                     style={{ minWidth: "max-content" }}>
                    {sorted.map((stage, idx) => {
                        const isConfirmed =
                            stage.confidence === "CONFIRMED"
                        const techId = getTechniqueId(
                            stage.mitre_technique
                        )
                        const assets = Array.isArray(
                            stage.affected_assets
                        )
                            ? stage.affected_assets
                            : []

                        return (
                            <React.Fragment key={idx}>
                                <div
                                    className={`
                                        flex flex-col gap-1.5 p-3
                                        bg-sentinel-bg rounded-lg
                                        border border-sentinel-border
                                        ${isConfirmed
                                            ? "border-l-4 border-l-green-500"
                                            : "border-l-4 border-l-amber-500"
                                        }
                                    `}
                                    style={{
                                        minWidth: "180px",
                                        maxWidth: "220px",
                                    }}
                                >
                                    {/* Stage number + confidence */}
                                    <div className="flex items-center
                                                    justify-between gap-1">
                                        <span className="text-xs
                                                         text-sentinel-muted">
                                            #{stage.stage_number ?? idx + 1}
                                        </span>
                                        <span className={`
                                            text-xs px-1.5 py-0.5
                                            rounded font-medium
                                            ${isConfirmed
                                                ? "bg-green-900 text-green-300"
                                                : "bg-amber-900 text-amber-300"
                                            }
                                        `}>
                                            {stage.confidence ?? "INFERRED"}
                                        </span>
                                    </div>

                                    {/* Stage name */}
                                    <p className="text-sm font-semibold
                                                  text-white leading-tight">
                                        {stage.stage_name ?? `Stage ${idx + 1}`}
                                    </p>

                                    {/* MITRE technique badge */}
                                    {techId && (
                                        <span className="text-xs px-1.5 py-0.5
                                                         rounded bg-blue-900
                                                         text-blue-300
                                                         w-fit font-mono">
                                            {techId}
                                        </span>
                                    )}

                                    {/* Timestamp */}
                                    {stage.timestamp && (
                                        <p className="text-xs
                                                      text-sentinel-muted">
                                            {stage.timestamp}
                                        </p>
                                    )}

                                    {/* Evidence */}
                                    {stage.evidence && (
                                        <p className="text-xs
                                                      text-sentinel-muted
                                                      leading-snug">
                                            {truncate(stage.evidence)}
                                        </p>
                                    )}

                                    {/* Affected assets */}
                                    {assets.length > 0 && (
                                        <p className="text-xs
                                                      text-sentinel-muted">
                                            {assets[0]}
                                            {assets.length > 1 && (
                                                <span className="text-sentinel-muted">
                                                    {" "}+{assets.length - 1} more
                                                </span>
                                            )}
                                        </p>
                                    )}
                                </div>

                                {/* Arrow between cards */}
                                {idx < sorted.length - 1 && (
                                    <div className="flex items-center
                                                    shrink-0 self-center
                                                    text-sentinel-muted
                                                    text-lg px-1">
                                        {">"}
                                    </div>
                                )}
                            </React.Fragment>
                        )
                    })}
                </div>
            </div>
        </div>
    )
}

export default KillChainTimeline
