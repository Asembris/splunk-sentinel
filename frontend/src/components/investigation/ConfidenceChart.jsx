import {
  LineChart, Line, XAxis, YAxis, Tooltip,
  ResponsiveContainer, ReferenceLine, Area, AreaChart
} from 'recharts'
import { useInvestigation } from '../../store/InvestigationContext'

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-lg px-3 py-2 text-xs">
      <p className="text-sentinel-muted mb-1">{label}</p>
      <p className="text-sentinel-accent font-bold">
        Confidence: {payload[0]?.value}%
      </p>
    </div>
  )
}

export default function ConfidenceChart() {
  const { state } = useInvestigation()

  const iterationMap = new Map()
  state.killChainStages.forEach(stage => {
    if (!iterationMap.has(stage.iteration)) {
      iterationMap.set(stage.iteration, Math.round(stage.confidence * 100))
    }
  })

  const chartData = [{ name: 'Start', confidence: 0 }]
  iterationMap.forEach((confidence, iteration) => {
    chartData.push({ name: `Iter ${iteration}`, confidence })
  })

  if (
    state.status === 'complete' &&
    state.result?.final_report?.investigation_confidence
  ) {
    chartData.push({
      name: 'Final',
      confidence: Math.round(
        state.result.final_report.investigation_confidence * 100
      ),
    })
  }

  const currentConf = Math.round(state.confidence * 100)

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-sentinel-muted uppercase tracking-wider">
            Confidence Progression
          </h3>
          <p className="text-xs text-sentinel-muted mt-0.5">
            Target threshold: 70%
          </p>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-bold ${
            currentConf >= 70 ? 'text-sentinel-success' : 'text-sentinel-accent'
          }`}>
            {currentConf}%
          </div>
          <div className="text-xs text-sentinel-muted">current</div>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={120}>
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="confidenceGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="name"
            tick={{ fill: '#6b7280', fontSize: 10 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fill: '#6b7280', fontSize: 10 }}
            axisLine={false}
            tickLine={false}
            tickFormatter={v => `${v}%`}
            width={36}
          />
          <Tooltip content={<CustomTooltip />} />
          <ReferenceLine
            y={70}
            stroke="#ef4444"
            strokeDasharray="4 4"
            strokeWidth={1.5}
            label={{
              value: '70% threshold',
              position: 'insideTopRight',
              fill: '#ef4444',
              fontSize: 10,
            }}
          />
          <Area
            type="monotone"
            dataKey="confidence"
            stroke="#3b82f6"
            strokeWidth={2.5}
            fill="url(#confidenceGrad)"
            dot={{ fill: '#3b82f6', r: 4, strokeWidth: 2, stroke: '#1e3a5f' }}
            activeDot={{ r: 6, fill: '#60a5fa' }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
