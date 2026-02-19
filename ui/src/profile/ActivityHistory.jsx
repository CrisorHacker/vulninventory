import "./ActivityHistory.css";

function formatRelative(timestamp) {
  const date = new Date(timestamp);
  const diffMs = Date.now() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 60) {
    return `Hace ${diffMins} minutos`;
  }
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) {
    return `Hace ${diffHours} horas`;
  }
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays === 1) {
    return "Ayer";
  }
  return `Hace ${diffDays} dias`;
}

function ActivityIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="activity-history__icon">
      <path
        d="M4 12h4l2-5 4 10 2-5h4"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function ActivityHistory({ activityLog = [] }) {
  return (
    <section className="activity-history">
      <div className="activity-history__header">
        <h3>Historial reciente</h3>
        <span>Ultimas actividades</span>
      </div>
      <div className="activity-history__timeline">
        {activityLog.map((item, index) => (
          <div key={`${item.action}-${index}`} className="activity-history__item">
            <div className="activity-history__marker">
              <ActivityIcon />
            </div>
            <div className="activity-history__content">
              <p className="activity-history__action">{item.action}</p>
              <div className="activity-history__meta">
                <span>{formatRelative(item.timestamp)}</span>
                {item.ip ? <span>IP {item.ip}</span> : null}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
