import ComingSoon from '../components/common/ComingSoon';
import { BellDot } from 'lucide-react';
export default function Alerts() {
  return <ComingSoon icon={BellDot} pageName="Alert Management" phase={5}
    description="Alerts fired by the detection engine, with acknowledge and close workflows, arrive in Phase 5." />;
}
