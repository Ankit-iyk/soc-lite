import ComingSoon from '../components/common/ComingSoon';
import { Settings as SettingsIcon } from 'lucide-react';
export default function Settings() {
  return <ComingSoon icon={SettingsIcon} pageName="Settings" phase={12}
    description="User management, access policies, and audit log configuration arrive in Phase 12." />;
}
