import "./ProfileHeader.css";

function getInitials(name) {
  if (!name) {
    return "?";
  }
  const parts = name.trim().split(/\s+/);
  const first = parts[0]?.[0] || "";
  const last = parts.length > 1 ? parts[parts.length - 1][0] : "";
  return (first + last).toUpperCase();
}

function CameraIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      className="profile-header__camera"
    >
      <path
        d="M8.5 6.5 10 4.5h4l1.5 2H19a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2h3.5Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="3.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

export default function ProfileHeader({ user, onAvatarChange }) {
  const initials = getInitials(user?.name);

  return (
    <header className="profile-header">
      <div className="profile-header__avatar" role="img" aria-label="Avatar de usuario">
        {user?.avatar ? (
          <img src={user.avatar} alt="Avatar" className="profile-header__avatar-img" />
        ) : (
          <div className="profile-header__avatar-fallback">{initials}</div>
        )}
        <button
          type="button"
          className="profile-header__avatar-action"
          onClick={onAvatarChange}
          aria-label="Cambiar foto de perfil"
        >
          <CameraIcon />
        </button>
      </div>
      <div className="profile-header__meta">
        <div className="profile-header__title-row">
          <h2 className="profile-header__name">{user?.name}</h2>
          <span className="profile-header__badge">{user?.role}</span>
        </div>
        <p className="profile-header__subtitle">{user?.position}</p>
        <p className="profile-header__email">{user?.email}</p>
      </div>
    </header>
  );
}
