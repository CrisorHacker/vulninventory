import { useEffect, useState } from "react";
import "./EditProfile.css";

export default function EditProfile({ user, onSave, onSuccess, requireName = false }) {
  const [form, setForm] = useState({
    fullName: user?.name || "",
    phone: user?.phone || "",
    position: user?.position || "",
  });
  const [status, setStatus] = useState({ type: "", message: "" });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setForm({
      fullName: user?.name || "",
      phone: user?.phone || "",
      position: user?.position || "",
    });
  }, [user]);

  function handleChange(event) {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  }

  function validate() {
    if (requireName && !form.fullName.trim()) {
      return "El nombre completo es obligatorio.";
    }
    if (!form.phone.trim()) {
      return "El celular es obligatorio.";
    }
    if (!/^[0-9+()\s-]+$/.test(form.phone)) {
      return "El celular solo debe contener numeros o simbolos validos.";
    }
    if (!form.position.trim()) {
      return "El cargo es obligatorio.";
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
        await onSave({
          full_name: form.fullName.trim(),
          phone: form.phone.trim(),
          title: form.position.trim(),
        });
      }
      setStatus({ type: "success", message: "Cambios guardados." });
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
    <section className="edit-profile">
      <div className="edit-profile__header">
        <h3>Editar perfil</h3>
        <span>Actualiza tu telefono y cargo.</span>
      </div>
      <form className="edit-profile__form" onSubmit={handleSubmit}>
        {requireName ? (
          <div className="edit-profile__field form-group">
            <label className="form-label" htmlFor="profile-name">Nombre completo</label>
            <input
              id="profile-name"
              name="fullName"
              type="text"
              value={form.fullName}
              onChange={handleChange}
              placeholder="Nombre completo"
              className="form-input"
            />
          </div>
        ) : null}
        <div className="edit-profile__field form-group">
          <label className="form-label" htmlFor="profile-phone">Celular</label>
          <input
            id="profile-phone"
            name="phone"
            type="tel"
            value={form.phone}
            onChange={handleChange}
            placeholder="Ej: 3001234567"
            className="form-input"
          />
        </div>
        <div className="edit-profile__field form-group">
          <label className="form-label" htmlFor="profile-position">Cargo</label>
          <input
            id="profile-position"
            name="position"
            type="text"
            value={form.position}
            onChange={handleChange}
            placeholder="Ej: Analista SOC"
            className="form-input"
          />
        </div>
        {status.message ? (
          <div
            className={
              status.type === "success"
                ? "edit-profile__status edit-profile__status--success"
                : "edit-profile__status edit-profile__status--error"
            }
          >
            {status.message}
          </div>
        ) : null}
        <button type="submit" className="btn btn-primary edit-profile__button" disabled={saving}>
          {saving ? "Guardando..." : "Guardar cambios"}
        </button>
      </form>
    </section>
  );
}
