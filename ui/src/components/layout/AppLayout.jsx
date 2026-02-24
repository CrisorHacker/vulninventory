import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";

export function AppLayout({ children }) {
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="app-content">{children || <Outlet />}</main>
    </div>
  );
}
