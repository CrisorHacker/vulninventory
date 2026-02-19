import { useEffect, useState } from "react";
import "./NotificationPreferences.css";

const preferenceItems = [
  {
    key: "criticalVulns",
    label: "Vulnerabilidades criticas (CVSS >= 9.0)",
    description: "Alertas inmediatas para riesgos criticos.",
  },
  {
    key: "assignedVulns",
    label: "Nuevas vulnerabilidades asignadas",
    description: "Recibe avisos cuando te asignan un hallazgo.",
  },
  {
    key: "statusUpdates",
    label: "Actualizaciones de estado",
    description: "Notificaciones cuando un hallazgo cambia de estado.",
  },
  {
    key: "reports",
    label: "Reportes generados",
    description: "Avisos de exportaciones o reportes en cola.",
  },
  {
    key: "systemAlerts",
    label: "Alertas del sistema",
    description: "Eventos relevantes del sistema o mantenimiento.",
  },
];

export default function NotificationPreferences({ notifications, onSave, onSuccess }) {
  const [settings, setSettings] = useState({
    ...notifications,
  });
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState("");

  useEffect(() => {
    if (notifications) {
      setSettings({ ...notifications });
    }
  }, [notifications]);

  function toggleSetting(key) {
    setSettings((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  function handleChannelChange(event) {
    setSettings((prev) => ({ ...prev, channel: event.target.value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setSaving(true);
    setStatus("");
    try {
      if (onSave) {
        await onSave(settings);
      }
      setStatus("Preferencias actualizadas.");
      if (onSuccess) {
        onSuccess();
      }
    } catch (err) {
      setStatus(err.message || "No se pudo guardar.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="notification-preferences">
      <div className="notification-preferences__header">
        <h3>Preferencias de notificaciones</h3>
        <span>Configura el canal y tipo de alertas.</span>
      </div>
      <form className="notification-preferences__form" onSubmit={handleSubmit}>
        <div className="notification-preferences__toggles">
          {preferenceItems.map((item) => (
            <div key={item.key} className="notification-preferences__row">
              <div>
                <p className="notification-preferences__label">{item.label}</p>
                <p className="notification-preferences__description">{item.description}</p>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={settings[item.key]}
                className={
                  settings[item.key]
                    ? "notification-preferences__toggle notification-preferences__toggle--on"
                    : "notification-preferences__toggle"
                }
                onClick={() => toggleSetting(item.key)}
              >
                <span className="notification-preferences__handle" />
              </button>
            </div>
          ))}
        </div>
        <div className="notification-preferences__channels">
          <p className="notification-preferences__label">Canal preferido</p>
          <div className="notification-preferences__options" role="radiogroup">
            {["email", "push", "ambos"].map((channel) => (
              <label key={channel} className="notification-preferences__option">
                <input
                  type="radio"
                  name="channel"
                  value={channel}
                  checked={settings.channel === channel}
                  onChange={handleChannelChange}
                />
                {channel}
              </label>
            ))}
          </div>
        </div>
        {status ? <div className="notification-preferences__status">{status}</div> : null}
        <button
          type="submit"
          className="btn btn-primary notification-preferences__button"
          disabled={saving}
        >
          {saving ? "Guardando..." : "Guardar preferencias"}
        </button>
      </form>
    </section>
  );
}
