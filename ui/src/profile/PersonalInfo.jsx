import "./PersonalInfo.css";

function InfoIcon({ type }) {
  const paths = {
    mail: "M4 6h16a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2Zm0 0 8 6 8-6",
    user: "M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm0 2c-4.4 0-8 2-8 4.5V20h16v-1.5c0-2.5-3.6-4.5-8-4.5Z",
    phone: "M5.5 3h3l2 5-2 1.5a14 14 0 0 0 6 6l1.5-2 5 2v3a2 2 0 0 1-2 2A15.5 15.5 0 0 1 3 5a2 2 0 0 1 2.5-2Z",
    briefcase:
      "M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2h4a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h4Zm2-2h4v2h-4V5Z",
  };
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="personal-info__icon">
      <path d={paths[type]} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

export default function PersonalInfo({ user }) {
  return (
    <section className="personal-info">
      <div className="personal-info__header">
        <h3>Informacion personal</h3>
        <span className="personal-info__note">Solo lectura</span>
      </div>
      <div className="personal-info__grid">
        <div className="personal-info__field">
          <label className="personal-info__label">
            <InfoIcon type="mail" /> Correo
          </label>
          <p className="personal-info__value">{user?.email}</p>
        </div>
        <div className="personal-info__field">
          <label className="personal-info__label">
            <InfoIcon type="user" /> Nombre completo
          </label>
          <p className="personal-info__value">{user?.name}</p>
        </div>
        <div className="personal-info__field">
          <label className="personal-info__label">
            <InfoIcon type="phone" /> Celular
          </label>
          <p className="personal-info__value">{user?.phone}</p>
        </div>
        <div className="personal-info__field">
          <label className="personal-info__label">
            <InfoIcon type="briefcase" /> Cargo
          </label>
          <p className="personal-info__value">{user?.position}</p>
        </div>
      </div>
    </section>
  );
}
