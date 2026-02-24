import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import { ProjectProvider } from "./context/ProjectContext";
import { ThemeProvider } from "./context/ThemeContext";
import { ProtectedRoute } from "./components/layout/ProtectedRoute";

import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import CompleteProfilePage from "./pages/CompleteProfilePage";
import RotatePasswordPage from "./pages/RotatePasswordPage";
import ForgotPasswordPage from "./pages/ForgotPasswordPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import DashboardPage from "./pages/DashboardPage";
import FindingsPage from "./pages/FindingsPage";
import AssetsPage from "./pages/AssetsPage";
import ScansPage from "./pages/ScansPage";
import TeamPage from "./pages/TeamPage";
import AuditPage from "./pages/AuditPage";
import ProfilePage from "./pages/ProfilePage";

const publicRoutes = [
  ["/login", <LoginPage />],
  ["/register", <RegisterPage />],
  ["/forgot-password", <ForgotPasswordPage />],
  ["/reset-password", <ResetPasswordPage />],
  ["/complete-profile", <CompleteProfilePage />],
  ["/rotate-password", <RotatePasswordPage />],
];

const protectedRoutes = [
  ["/", <Navigate to="/dashboard" replace />],
  ["/dashboard", <DashboardPage />],
  ["/findings", <FindingsPage />],
  ["/assets", <AssetsPage />],
  ["/scans", <ScansPage />],
  ["/team", <TeamPage />],
  ["/audit", <AuditPage />],
  ["/profile", <ProfilePage />],
];

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <ProjectProvider>
            <Routes>
              {publicRoutes.map(([path, element]) => (
                <Route key={path} path={path} element={element} />
              ))}
              {protectedRoutes.map(([path, element]) => (
                <Route
                  key={path}
                  path={path}
                  element={<ProtectedRoute>{element}</ProtectedRoute>}
                />
              ))}
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          </ProjectProvider>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}
