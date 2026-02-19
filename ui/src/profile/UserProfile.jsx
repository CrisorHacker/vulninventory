import { useMemo, useState } from "react";
import ProfileHeader from "./ProfileHeader";
import PersonalInfo from "./PersonalInfo";
import EditProfile from "./EditProfile";
import ChangePassword from "./ChangePassword";
import ActivityHistory from "./ActivityHistory";
import NotificationPreferences from "./NotificationPreferences";
import "./UserProfile.css";

const mockUser = {
  name: "Cristhian Fernando Roncancio",
  email: "crisor@prueba.com",
  phone: "3235792535",
  position: "Especialista Ciberseguridad",
  role: "Analista",
  avatar: null,
  activityLog: [
    { action: "Inició sesión", timestamp: "2025-02-17T08:30:00", ip: "192.168.1.45" },
    { action: "Registró vulnerabilidad CVE-2025-1234", timestamp: "2025-02-17T09:15:00" },
    { action: "Actualizó estado de CVE-2025-0987 a 'Mitigada'", timestamp: "2025-02-16T16:40:00" },
    { action: "Exportó reporte mensual", timestamp: "2025-02-16T11:00:00" },
    { action: "Cambió contraseña", timestamp: "2025-02-15T14:20:00" },
  ],
  notifications: {
    criticalVulns: true,
    assignedVulns: true,
    statusUpdates: false,
    reports: true,
    systemAlerts: true,
    channel: "email",
  },
};

export default function UserProfile({
  user = mockUser,
  requiresProfile = false,
  onProfileSave,
  onPasswordSave,
  onNotificationSave,
}) {
  const [toast, setToast] = useState("");

  const profileData = useMemo(() => user || mockUser, [user]);

  function showToast(message) {
    setToast(message);
    window.setTimeout(() => setToast(""), 2400);
  }

  return (
    <section className="profile-page" aria-live="polite">
      {toast ? <div className="profile-page__toast">{toast}</div> : null}
      {requiresProfile ? (
        <div className="profile-page__banner">
          Completa tu perfil para continuar usando la aplicación.
        </div>
      ) : null}
      <ProfileHeader user={profileData} onAvatarChange={() => showToast("Avatar actualizado")} />
      <div className="profile-page__grid">
        <div className="profile-page__column">
          <PersonalInfo user={profileData} />
          <EditProfile
            user={profileData}
            onSave={onProfileSave}
            onSuccess={() => showToast("Perfil actualizado")}
            requireName={requiresProfile && !profileData?.name}
          />
        </div>
        <div className="profile-page__column">
          <ChangePassword onSave={onPasswordSave} onSuccess={() => showToast("Contraseña actualizada")} />
          <NotificationPreferences
            notifications={profileData.notifications}
            onSave={onNotificationSave}
            onSuccess={() => showToast("Preferencias guardadas")}
          />
        </div>
      </div>
      <ActivityHistory activityLog={profileData.activityLog} />
    </section>
  );
}
