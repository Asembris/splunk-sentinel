import { createContext, useContext, useReducer, useCallback } from 'react'
import { nanoid } from 'nanoid'
import { streamInvestigation } from '../lib/sse'

const InvestigationContext = createContext(null)

const initialState = {
  status: 'idle',         // idle | running | complete | error
  investigationId: null,
  trigger: '',
  agentStatuses: {
    triage_agent: 'waiting',
    reconstruction_agent: 'waiting',
    threat_intel_agent: 'waiting',
    ttp_agent: 'waiting',
    synthesis_agent: 'waiting',
  },
  currentIteration: 0,
  totalIterations: 3,
  confidence: 0,
  killChainStages: [],
  events: [],
  result: null,
  error: null,
}

function reducer(state, action) {
  switch (action.type) {

    case 'START_INVESTIGATION':
      return {
        ...initialState,
        status: 'running',
        investigationId: action.investigationId,
        trigger: action.trigger,
        events: [{
          time: new Date().toISOString(),
          type: 'system',
          message: 'Investigation started',
        }],
      }

    case 'AGENT_PROGRESS': {
      const stage = action.stage
      const newStatuses = { ...state.agentStatuses }

      // Handle non-agent metadata stages (like 'started')
      if (!newStatuses[stage]) {
        return {
          ...state,
          events: [...state.events, {
            time: new Date().toISOString(),
            type: 'system',
            message: `Pipeline status: ${stage}`,
          }],
        }
      }

      // Mark previous agents complete
      const agentOrder = [
        'triage_agent', 'reconstruction_agent',
        'threat_intel_agent', 'ttp_agent', 'synthesis_agent'
      ]
      const idx = agentOrder.indexOf(stage)
      if (idx > 0) {
        agentOrder.slice(0, idx).forEach(a => {
          newStatuses[a] = 'complete'
        })
      }
      newStatuses[stage] = 'running'

      const agentLabels = {
        triage_agent: 'Triage Agent',
        reconstruction_agent: 'Reconstruction Agent',
        threat_intel_agent: 'Threat Intel Agent',
        ttp_agent: 'TTP Agent',
        synthesis_agent: 'Synthesis Agent',
      }

      return {
        ...state,
        agentStatuses: newStatuses,
        events: [...state.events, {
          time: new Date().toISOString(),
          type: 'agent',
          message: `${agentLabels[stage] || stage} started`,
        }],
      }
    }

    case 'RECONSTRUCTION_PROGRESS': {
      const { iteration, new_stages, confidence, gaps_remaining, evidence } = action.data

      // Build new kill chain nodes from stage names
      const newStages = (new_stages || []).map((stageName, i) => ({
        id: `stage-${iteration}-${i}`,
        label: stageName,
        iteration,
        confidence: confidence,
        evidence: evidence?.[stageName] || evidence?.[i] || null,
        discovered_at: new Date().toISOString(),
      }))

      const stageEvents = (new_stages || []).map(s => ({
        time: new Date().toISOString(),
        type: 'stage',
        message: `Stage discovered: ${s}`,
      }))

      return {
        ...state,
        currentIteration: iteration,
        confidence: confidence,
        killChainStages: [...state.killChainStages, ...newStages],
        events: [
          ...state.events,
          {
            time: new Date().toISOString(),
            type: 'iteration',
            message: `Reconstruction iteration ${iteration} · confidence ${(confidence * 100).toFixed(0)}% · ${gaps_remaining} gaps`,
          },
          ...stageEvents,
        ],
      }
    }

    case 'COMPLETE': {
      // Backfill evidence/details from final report if missing
      const finalStages = action.data?.final_report?.key_findings || []
      const enrichedStages = state.killChainStages.map(stage => {
        const finding = finalStages.find(f => 
          f.finding.toLowerCase().includes(stage.label.toLowerCase()) ||
          stage.label.toLowerCase().includes(f.finding.toLowerCase())
        )
        return finding ? { ...stage, evidence: finding.evidence || stage.evidence } : stage
      })

      return {
        ...state,
        status: 'complete',
        result: action.data,
        killChainStages: enrichedStages,
        agentStatuses: Object.fromEntries(
          Object.keys(state.agentStatuses).map(k => [k, 'complete'])
        ),
        events: [...state.events, {
          time: new Date().toISOString(),
          type: 'complete',
          message: `Investigation complete · confidence ${((action.data?.final_report?.investigation_confidence || 0) * 100).toFixed(0)}%`,
        }],
      }
    }

    case 'ERROR':
      return {
        ...state,
        status: 'error',
        error: action.error,
        events: [...state.events, {
          time: new Date().toISOString(),
          type: 'error',
          message: `Error: ${action.error}`,
        }],
      }

    case 'UPDATE_CONTAINMENT_PLAN':
      if (!state.result) return state;
      return {
        ...state,
        result: {
          ...state.result,
          final_report: {
            ...state.result.final_report,
            containment_plan: action.plan
          }
        }
      }

    default:
      return state
  }
}

export function InvestigationProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState)

  const startInvestigation = useCallback(async (trigger) => {
    const investigationId = `sentinel-${Date.now()}`

    dispatch({
      type: 'START_INVESTIGATION',
      investigationId,
      trigger,
    })

    await streamInvestigation({
      trigger,
      investigationId,
      onEvent: (eventType, data) => {
        console.debug(`[SSE] ${eventType}:`, data)
        if (eventType === 'progress') {
          dispatch({ type: 'AGENT_PROGRESS', stage: data.stage })
        } else if (eventType === 'reconstruction_progress') {
          dispatch({ type: 'RECONSTRUCTION_PROGRESS', data })
        }
      },
      onComplete: (data) => {
        dispatch({ type: 'COMPLETE', data })
      },
      onError: (error) => {
        dispatch({ type: 'ERROR', error: error.message })
      },
    })
  }, [])

  return (
    <InvestigationContext.Provider value={{ state, startInvestigation, dispatch }}>
      {children}
    </InvestigationContext.Provider>
  )
}

export function useInvestigation() {
  const ctx = useContext(InvestigationContext)
  if (!ctx) throw new Error('useInvestigation must be used inside InvestigationProvider')
  return ctx
}
