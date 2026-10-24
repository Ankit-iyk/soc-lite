import ComingSoon from '../components/common/ComingSoon';
import { Shield } from 'lucide-react';
export default function ThreatIntel() {
  return <ComingSoon icon={Shield} pageName="Threat Intelligence" phase={9}
    description="Local IOC list (IPs, domains, hashes), bulk import, and wiring to the Suspicious IP rule arrive in Phase 9." />;
}
