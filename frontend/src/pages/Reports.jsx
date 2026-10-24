import ComingSoon from '../components/common/ComingSoon';
import { FileText } from 'lucide-react';
export default function Reports() {
  return <ComingSoon icon={FileText} pageName="Security Reports" phase={10}
    description="PDF report generation and download based on real incident and alert data arrives in Phase 10." />;
}
