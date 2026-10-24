// src/components/common/ComingSoon.jsx
// Reusable placeholder shown on pages not yet implemented.
// Each page passes its own icon, name, and phase number.

export default function ComingSoon({ icon: Icon, pageName, phase, description }) {
  return (
    <div className="coming-soon fade-in">
      <div className="coming-soon-icon">
        {Icon && <Icon size={24} color="var(--color-text-muted)" />}
      </div>
      <h2>{pageName}</h2>
      <p>{description ?? `This section will be built in Phase ${phase}.`}</p>
      <span className="badge badge-info">Phase {phase}</span>
    </div>
  );
}
