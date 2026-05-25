import { Component } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom'
import { InvestigationProvider } from './store/InvestigationContext'
import Navbar from './components/layout/Navbar'
import InvestigatePage from './pages/InvestigatePage'
import DashboardPage from './pages/DashboardPage'
import ReportPage from './pages/ReportPage'
import HistoryPage from './pages/HistoryPage'

class ReportRouteBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error) {
    console.error('[ReportRouteBoundary] Report route crashed:', error)
  }

  componentDidUpdate(prevProps) {
    if (
      prevProps.resetKey !== this.props.resetKey &&
      this.state.hasError
    ) {
      this.setState({ hasError: false })
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="max-w-3xl mx-auto px-6 py-10">
          <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-2">
              Report Unavailable
            </h2>
            <p className="text-sm text-sentinel-muted">
              This report view hit a render error. Please refresh, or open another report from History.
            </p>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

function ReportRouteWithBoundary() {
  const { id } = useParams()
  return (
    <ReportRouteBoundary resetKey={id || '__no_id__'}>
      <ReportPage />
    </ReportRouteBoundary>
  )
}

export default function App() {
  return (
    <InvestigationProvider>
      <BrowserRouter>
        <div className="min-h-screen bg-sentinel-bg">
          <Navbar />
          <Routes>
            <Route path="/" element={<InvestigatePage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/report/:id?" element={<ReportRouteWithBoundary />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </div>
      </BrowserRouter>
    </InvestigationProvider>
  )
}
