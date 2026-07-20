import { BrowserRouter, Routes, Route, Navigate, useParams, Outlet } from 'react-router-dom';
import { SignIn, SignUp, useAuth } from '@clerk/react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import PortScanner from './views/PortScanner';
import WebAppScanner from './views/WebAppScanner';
import DNSLookup from './views/DNSLookup';
import Whois from './views/Whois';
import Traceroute from './views/Traceroute';
import SSL from './views/SSL';
import GenericTool from './views/GenericTool';
import AIExecutiveReport from './views/AIExecutiveReport';
import Dashboard from './views/Dashboard';
import { TierProvider } from './context/TierContext';
import UpgradeModal from './components/UpgradeModal';

function DynamicTool() {
  const { toolId } = useParams();
  if (toolId === 'dns') return <DNSLookup />;
  if (toolId === 'whois') return <Whois />;
  if (toolId === 'webscan') return <WebAppScanner />;
  if (toolId === 'traceroute') return <Traceroute />;
  if (toolId === 'ssl') return <SSL />;
  return <GenericTool toolId={toolId} />;
}

function RequireAuth() {
  const { isLoaded, isSignedIn } = useAuth();

  if (!isLoaded) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <span className="tier-badge free">Loading…</span>
      </div>
    );
  }

  if (!isSignedIn) {
    return <Navigate to="/sign-in" replace />;
  }

  return (
    <TierProvider>
      <Navbar />
      <div className="app-main-layout flex">
        <Sidebar />
        <main className="flex-1 flex flex-col app-content-panel min-w-0">
          <Outlet />
        </main>
      </div>
      <UpgradeModal />
    </TierProvider>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <Routes>
          <Route path="/sign-in/*" element={<SignIn routing="path" path="/sign-in" />} />
          <Route path="/sign-up/*" element={<SignUp routing="path" path="/sign-up" />} />

          <Route element={<RequireAuth />}>
            <Route path="/" element={<Navigate to="/tools/portscanner" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/tools/portscanner" element={<PortScanner />} />
            <Route path="/tools/webscan" element={<WebAppScanner />} />
            <Route path="/tools/:toolId" element={<DynamicTool />} />
            <Route path="/executive-report" element={<AIExecutiveReport />} />
          </Route>

          <Route path="*" element={<Navigate to="/sign-in" replace />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

