import { useEffect, useRef, useState } from 'react'
import { Network } from 'vis-network'
import { DataSet } from 'vis-data'
import { useInvestigation } from '../../store/InvestigationContext'

const TACTIC_COLORS = {
  'TA0001': '#ef4444', // Initial Access - red
  'TA0002': '#f97316', // Execution - orange
  'TA0003': '#eab308', // Persistence - yellow
  'TA0004': '#a855f7', // Privilege Escalation - purple
  'TA0005': '#6366f1', // Defense Evasion - indigo
  'TA0006': '#ec4899', // Credential Access - pink
  'TA0007': '#14b8a6', // Discovery - teal
  'TA0008': '#f59e0b', // Lateral Movement - amber
  'TA0009': '#84cc16', // Collection - lime
  'TA0010': '#06b6d4', // Exfiltration - cyan
  'TA0011': '#8b5cf6', // Command and Control - violet
  'TA0040': '#dc2626', // Impact - dark red
}

function getNodeColor(stageName) {
  for (const [tactic, color] of Object.entries(TACTIC_COLORS)) {
    if (stageName.includes(tactic)) return color
  }
  // Infer from stage name keywords
  if (stageName.toLowerCase().includes('initial') || stageName.toLowerCase().includes('access')) return TACTIC_COLORS['TA0001']
  if (stageName.toLowerCase().includes('execut')) return TACTIC_COLORS['TA0002']
  if (stageName.toLowerCase().includes('credential') || stageName.toLowerCase().includes('iam')) return TACTIC_COLORS['TA0006']
  if (stageName.toLowerCase().includes('lateral')) return TACTIC_COLORS['TA0008']
  if (stageName.toLowerCase().includes('evasion') || stageName.toLowerCase().includes('log')) return TACTIC_COLORS['TA0005']
  if (stageName.toLowerCase().includes('impact') || stageName.toLowerCase().includes('encrypt')) return TACTIC_COLORS['TA0040']
  return '#3b82f6'
}

const VIS_OPTIONS = {
  nodes: {
    shape: 'box',
    margin: { top: 12, bottom: 12, left: 16, right: 16 },
    font: { color: '#f9fafb', size: 12, face: 'Inter, system-ui', bold: { color: '#ffffff' } },
    borderWidth: 2,
    borderWidthSelected: 3,
    shadow: { enabled: true, color: 'rgba(0,0,0,0.6)', size: 10, x: 2, y: 2 },
    widthConstraint: { minimum: 140, maximum: 200 },
  },
  edges: {
    arrows: { to: { enabled: true, scaleFactor: 0.7 } },
    color: { color: '#374151', highlight: '#3b82f6', hover: '#3b82f6' },
    smooth: { type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.5 },
    width: 2,
    selectionWidth: 3,
  },
  layout: {
    hierarchical: {
      enabled: true,
      direction: 'LR',
      sortMethod: 'directed',
      nodeSpacing: 120,
      levelSeparation: 180,
      blockShifting: true,
      edgeMinimization: true,
    },
  },
  physics: { enabled: false },
  interaction: {
    hover: true,
    tooltipDelay: 100,
    zoomView: true,
    dragView: true,
    navigationButtons: false,
  },
}

export default function KillChainGraph() {
  const { state } = useInvestigation()
  const [isFullscreen, setIsFullscreen] = useState(false)
  const containerRef = useRef(null)
  const networkRef = useRef(null)
  const nodesRef = useRef(new DataSet([]))
  const edgesRef = useRef(new DataSet([]))
  const stageCountRef = useRef(0)

  // Initialize network
  useEffect(() => {
    if (!containerRef.current) return

    networkRef.current = new Network(
      containerRef.current,
      { nodes: nodesRef.current, edges: edgesRef.current },
      {
        ...VIS_OPTIONS,
        layout: {
          ...VIS_OPTIONS.layout,
          hierarchical: {
            ...VIS_OPTIONS.layout.hierarchical,
            nodeSpacing: isFullscreen ? 200 : 140,
            levelSeparation: isFullscreen ? 250 : 180,
          }
        }
      }
    )

    // Handle container resize
    const handleResize = () => {
      if (networkRef.current) {
        networkRef.current.redraw()
        networkRef.current.fit()
      }
    }
    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
      networkRef.current?.destroy()
      networkRef.current = null
    }
  }, [isFullscreen]) // Re-init on fullscreen toggle to apply new spacing

  // Add nodes as stages are discovered
  useEffect(() => {
    const stages = state.killChainStages
    if (stages.length <= stageCountRef.current) return

    const newStages = stages.slice(stageCountRef.current)
    const totalOldCount = stageCountRef.current
    stageCountRef.current = stages.length

    newStages.forEach((stage, i) => {
      const nodeId = stage.id
      const prevNodeId = stages[totalOldCount + i - 1]?.id

      const color = getNodeColor(stage.label)

      nodesRef.current.add({
        id: nodeId,
        label: stage.label.replace(/\s*[-\u2013]\s*/g, '\n'),
        title: `
          <div style="
            background:#111827;
            border:1px solid #374151;
            border-radius:8px;
            padding:10px 14px;
            font-family:monospace;
            font-size:12px;
            max-width:280px;
            color:#f9fafb;
          ">
            <div style="color:#3b82f6;font-weight:bold;margin-bottom:6px;">
              ${stage.label}
            </div>
            <div style="color:#6b7280;font-size:11px;">
              Iteration: ${stage.iteration} - 
              Confidence: ${Math.round(stage.confidence * 100)}%
            </div>
            ${stage.evidence ? `
              <div style="margin-top:6px;color:#d1d5db;font-size:11px;border-top:1px solid #374151;padding-top:6px;">
                ${stage.evidence.slice(0, 150)}
              </div>
            ` : ''}
          </div>
        `,
        color: {
          background: color + '33',
          border: color,
          highlight: { background: color + '66', border: color },
          hover: { background: color + '55', border: color },
        },
        level: totalOldCount + i,
      })

      // Add edge from previous node
      if (prevNodeId) {
        edgesRef.current.add({
          id: `edge-${prevNodeId}-${nodeId}`,
          from: prevNodeId,
          to: nodeId,
        })
      }
    })

    const timer = setTimeout(() => {
      if (networkRef.current) {
        networkRef.current.fit({
          animation: { duration: 600, easingFunction: 'easeInOutQuad' },
          padding: isFullscreen ? 80 : 40,
        })
      }
    }, 150)

    return () => clearTimeout(timer)
  }, [state.killChainStages, isFullscreen])

  const isEmpty = state.killChainStages.length === 0
  const isIdle = state.status === 'idle'

  return (
    <div className={`
      bg-sentinel-surface border border-sentinel-border rounded-xl overflow-hidden transition-all duration-300 shadow-2xl
      ${isFullscreen ? 'fixed inset-0 z-[100] rounded-none m-0' : 'relative'}
    `} style={{ height: isFullscreen ? '100vh' : '520px' }}>
      
      <div className="flex items-center justify-between px-6 py-4 border-b border-sentinel-border bg-sentinel-surface/50 backdrop-blur-md z-10 relative">
        <div className="flex items-center gap-3">
          <div className={`w-2 h-2 rounded-full ${isIdle ? 'bg-sentinel-muted' : 'bg-sentinel-success animate-pulse'}`} />
          <h3 className="text-xs font-bold text-sentinel-muted uppercase tracking-[0.2em]">
            Kill Chain Reconstruction
          </h3>
        </div>
        
        <div className="flex items-center gap-4">
          <span className="text-[10px] text-sentinel-muted font-mono bg-sentinel-bg px-2 py-1 rounded border border-sentinel-border">
            {state.killChainStages.length} NODES DISCOVERED
          </span>
          <button 
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-2 hover:bg-sentinel-bg rounded-lg transition-colors group"
            title={isFullscreen ? "Exit Fullscreen" : "Enter Fullscreen"}
          >
            {isFullscreen ? (
              <svg className="w-4 h-4 text-sentinel-muted group-hover:text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            ) : (
              <svg className="w-4 h-4 text-sentinel-muted group-hover:text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
              </svg>
            )}
          </button>
        </div>
      </div>

      <div 
        ref={containerRef} 
        className="w-full h-full absolute inset-0 pt-14 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px]" 
        style={{ height: '100%' }} 
      />

      {/* Empty state overlay */}
      {(isEmpty || isIdle) && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20 bg-sentinel-bg/40 backdrop-blur-[2px]">
          <div className="text-center">
            <div className="w-16 h-16 border border-sentinel-accent/30 rounded-full flex items-center justify-center mx-auto mb-4 animate-pulse bg-sentinel-accent/5">
              <span className="text-sentinel-accent text-2xl font-light">{'\u2B22'}</span>
            </div>
            <p className="text-sentinel-muted text-xs uppercase tracking-widest px-10">
              {isIdle ? 'Waiting for Investigation' : 'Reconstructing attack kill chain...'}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
