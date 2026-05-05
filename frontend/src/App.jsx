import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { InvestigationProvider } from './store/InvestigationContext'
import Navbar from './components/layout/Navbar'
import InvestigatePage from './pages/InvestigatePage'
import DashboardPage from './pages/DashboardPage'
import ReportPage from './pages/ReportPage'
import HistoryPage from './pages/HistoryPage'

export default function App() {
  return (
    <InvestigationProvider>
      <BrowserRouter>
        <div className="min-h-screen bg-sentinel-bg">
          <Navbar />
          <Routes>
            <Route path="/" element={<InvestigatePage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/report" element={<ReportPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </div>
      </BrowserRouter>
    </InvestigationProvider>
  )
}
