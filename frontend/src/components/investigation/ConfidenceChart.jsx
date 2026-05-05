import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts'
import { useInvestigation } from '../../store/InvestigationContext'

export default function ConfidenceChart() {
  const { state } = useInvestigation()

  // Build chart data from kill chain stages
  const chartData = [
    { name: 'Start', confidence: 0 },
    ...state.killChainStages
      .filter((_, i) => i === 0 || state.killChainStages[i].iteration !== state.killChainStages[i-1].iteration)
      .map((stage) => ({
        name: `Iter ${stage.iteration}`,
        confidence: Math.round(stage.confidence * 100),
      })),
  ]

  if (state.status === 'complete' && state.result?.final_report?.investigation_confidence) {
    chartData.push({
      name: 'Final',
      confidence: Math.round(state.result.final_report.investigation_confidence * 100),
    })
  }

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4 shadow-lg">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider">
          Confidence Progression
        </h3>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-sentinel-accent" />
            <span className="text-[10px] text-sentinel-muted uppercase">Confidence</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-0.5 bg-sentinel-border border-t border-dashed" />
            <span className="text-[10px] text-sentinel-muted uppercase">Threshold (70%)</span>
          </div>
        </div>
      </div>
      <div style={{ width: '100%', height: 100 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <XAxis 
              dataKey="name" 
              hide
            />
            <YAxis domain={[0, 100]} hide />
            <Tooltip
              contentStyle={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', fontSize: '11px' }}
              labelStyle={{ color: '#6b7280', marginBottom: '4px' }}
              itemStyle={{ color: '#3b82f6', padding: 0 }}
              formatter={v => [`${v}%`, 'Confidence']}
            />
            <ReferenceLine y={70} stroke="#1f2937" strokeDasharray="3 3" />
            <Line
              type="monotone"
              dataKey="confidence"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={{ fill: '#3b82f6', r: 4, strokeWidth: 0 }}
              activeDot={{ r: 6, strokeWidth: 0 }}
              animationDuration={1500}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
