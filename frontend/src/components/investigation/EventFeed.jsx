import { useEffect, useRef } from 'react'
import { useInvestigation } from '../../store/InvestigationContext'

const EVENT_STYLES = {
  system:    'text-sentinel-muted',
  agent:     'text-sentinel-accent font-medium',
  iteration: 'text-sentinel-warning',
  stage:     'text-sentinel-success',
  complete:  'text-sentinel-success font-bold',
  error:     'text-sentinel-danger',
}

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString('en-US', {
      hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
    })
  } catch (e) {
    return '--:--:--'
  }
}

export default function EventFeed() {
  const { state } = useInvestigation()
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [state.events])

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl overflow-hidden h-full shadow-lg" style={{ height: '420px' }}>
      <div className="px-4 py-3 border-b border-sentinel-border">
        <h3 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider">
          Forensic Event Feed
        </h3>
      </div>
      <div className="overflow-y-auto p-3 space-y-1.5 font-mono text-[11px] leading-relaxed scroll-smooth" style={{ height: '375px' }}>
        {state.events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full opacity-30">
            <div className="w-1 h-12 bg-sentinel-border mb-2" />
            <p className="text-sentinel-muted text-center italic">
              Initializing stream...
            </p>
          </div>
        ) : (
          state.events.map((event, i) => (
            <div key={i} className="flex gap-2 animate-fade-in group">
              <span className="text-sentinel-muted/60 flex-shrink-0 tabular-nums">
                {formatTime(event.time)}
              </span>
              <span className={EVENT_STYLES[event.type] || 'text-white'}>
                {event.message}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} className="h-4" />
      </div>
    </div>
  )
}
