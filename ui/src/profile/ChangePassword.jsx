import { useMemo, useState } from "react";
import "./ChangePassword.css";

function EyeIcon({ hidden }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="change-password__eye">
      {hidden ? (
        <path
          d="M3 5l18 14M10.6 10.9a3 3 0 0 0 4.2 4.2M9.5 5.8A9.6 9.6 0 0 1 12 5c5 0 9.3 3.2 11 7-0.5 1.3-1.2 2.4-2.1 3.4M6.1 7.2A11.6 11.6 0 0 0 1 12c1.9 4.2 6.4 7 11 7 1.2 0 2.4-0.2 3.5-0.6"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      ) : (
        <path
          d="M1 12c2-4.2 6.4-7 11-7s9 2.8 11 7c-2 4.2-6.4 7-11 7S3 16.2 1 12Zm11-4a4 4 0 1 0 4 4 4 4 0 0 0-4-4Z"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
    </svg>
  );
}

function scorePassword(value) {
  let score = 0;
  if (value.length >= 12) score += 1;
  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1;
  if (/[0-9]/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  return score;
}

export default function ChangePassword({ onSave, onSuccess }) {
  const [form, setForm] = useState({
    current: "",
    next: "",
    confirm: "",
  });
  const [visible, setVisible] = useState({ current: false, next: false, confirm: false });
  const [status, setStatus] = useState({ type: "", message: "" });
  const [saving, setSaving] = useState(false);

  const strength = useMemo(() => scorePassword(form.next), [form.next]);

  function handleChange(event) {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  }

  function validate() {
    if (!form.current) {
      return "Ingresa tu contraseña actual.";
    }
    if (form.next.length < 12) {
      return "La nueva contraseña debe tener al menos 12 caracteres.";
    }
    if (form.next !== form.confirm) {
      return "La confirmación no coincide.";
    }
    return "";
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const error = validate();
    if (error) {
      setStatus({ type: "error", message: error });
      return;
    }
    setSaving(true);
    setStatus({ type: "", message: "" });
    try {
      if (onSave) {
        await onSave({ current_password: form.current, new_password: form.next });
      }
      setStatus({ type: "success", message: "Contraseña actualizada." });
      setForm({ current: "", next: "", confirm: "" });
      if (onSuccess) {
        onSuccess();
      }
    } catch (err) {
      setStatus({ type: "error", message: err.message || "No se pudo actualizar." });
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="change-password">
      <div className="change-password__header">
        <h3>Cambiar contraseña</h3>
        <span>Requiere 12+ caracteres y complejidad.</span>
      </div>
      <form className="change-password__form" onSubmit={handleSubmit}>
        <div className="change-password__field form-group">
          <label className="form-label" htmlFor="current-password">Contraseña actual</label>
          <div className="change-password__input-wrapper">
            <input
              id="current-password"
              name="current"
              type={visible.current ? "text" : "password"}
              value={form.current}
              onChange={handleChange}
              className="form-input"
            />
            <button
              type="button"
              className="change-password__toggle"
              onClick={() => setVisible((prev) => ({ ...prev, current: !prev.current }))}
              aria-label="Mostrar contraseña actual"
            >
              <EyeIcon hidden={!visible.current} />
            </button>
          </div>
        </div>
        <div className="change-password__field form-group">
          <label className="form-label" htmlFor="new-password">Nueva contraseña</label>
          <div className="change-password__input-wrapper">
            <input
              id="new-password"
              name="next"
              type={visible.next ? "text" : "password"}
              value={form.next}
              onChange={handleChange}
              className="form-input"
            />
            <button
              type="button"
              className="change-password__toggle"
              onClick={() => setVisible((prev) => ({ ...prev, next: !prev.next }))}
              aria-label="Mostrar nueva contraseña"
            >
              <EyeIcon hidden={!visible.next} />
            </button>
          </div>
          <div className="change-password__strength">
            <div
              className={`change-password__strength-bar change-password__strength-bar--${strength}`}
            />
            <span>
              {strength <= 1
                ? "Débil"
                : strength === 2
                  ? "Media"
                  : strength === 3
                    ? "Fuerte"
                    : "Muy fuerte"}
            </span>
          </div>
        </div>
        <div className="change-password__field form-group">
          <label className="form-label" htmlFor="confirm-password">Confirmar nueva contraseña</label>
          <div className="change-password__input-wrapper">
            <input
              id="confirm-password"
              name="confirm"
              type={visible.confirm ? "text" : "password"}
              value={form.confirm}
              onChange={handleChange}
              className="form-input"
            />
            <button
              type="button"
              className="change-password__toggle"
              onClick={() => setVisible((prev) => ({ ...prev, confirm: !prev.confirm }))}
              aria-label="Mostrar confirmación"
            >
              <EyeIcon hidden={!visible.confirm} />
            </button>
          </div>
        </div>
        {status.message ? (
          <div
            className={
              status.type === "success"
                ? "change-password__status change-password__status--success"
                : "change-password__status change-password__status--error"
            }
          >
            {status.message}
          </div>
        ) : null}
        <button type="submit" className="btn btn-primary change-password__button" disabled={saving}>
          {saving ? "Actualizando..." : "Actualizar contraseña"}
        </button>
      </form>
    </section>
  );
}
