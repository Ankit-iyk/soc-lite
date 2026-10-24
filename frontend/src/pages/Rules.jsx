import ComingSoon from '../components/common/ComingSoon';
import { SlidersHorizontal } from 'lucide-react';
export default function Rules() {
  return <ComingSoon icon={SlidersHorizontal} pageName="Detection Rules" phase={4}
    description="View, enable/disable, and configure SSH Brute Force, Port Scan, Suspicious IP, and Suspicious Access rules in Phase 4." />;
}
