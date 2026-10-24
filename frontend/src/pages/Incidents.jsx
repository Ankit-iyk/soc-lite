import ComingSoon from '../components/common/ComingSoon';
import { FolderOpen } from 'lucide-react';
export default function Incidents() {
  return <ComingSoon icon={FolderOpen} pageName="Incident Tracking" phase={6}
    description="Incident creation, alert linking, investigation timeline, and status workflow arrive in Phase 6." />;
}
