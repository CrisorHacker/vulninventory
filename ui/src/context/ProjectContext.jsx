import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useAuth } from "./AuthContext";

const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:9292";

const ProjectContext = createContext(null);

export function ProjectProvider({ children, autoFetch = false }) {
  const { isAuthenticated } = useAuth();
  const [organizations, setOrganizations] = useState([]);
  const [projects, setProjects] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState(null);
  const [selectedProject, setSelectedProject] = useState(null);

  const fetchOrganizations = useCallback(async () => {
    if (!isAuthenticated) {
      setOrganizations([]);
      setSelectedOrg(null);
      return;
    }
    try {
      const resp = await fetch(`${API_BASE}/orgs`, { credentials: "include" });
      if (resp.ok) {
        const data = await resp.json();
        setOrganizations(data);
        if (data.length > 0 && !selectedOrg) {
          setSelectedOrg(data[0]);
        }
      }
    } catch (error) {
      console.error("Error fetching orgs:", error);
    }
  }, [isAuthenticated, selectedOrg]);

  const fetchProjects = useCallback(async (orgId) => {
    if (!orgId) {
      setProjects([]);
      setSelectedProject(null);
      return;
    }
    try {
      const resp = await fetch(`${API_BASE}/orgs/${orgId}/projects`, { credentials: "include" });
      if (resp.ok) {
        const data = await resp.json();
        setProjects(data);
        if (data.length > 0 && !selectedProject) {
          setSelectedProject(data[0]);
        }
      }
    } catch (error) {
      console.error("Error fetching projects:", error);
    }
  }, [selectedProject]);

  useEffect(() => {
    if (autoFetch) {
      fetchOrganizations();
    }
  }, [fetchOrganizations, autoFetch]);

  useEffect(() => {
    if (autoFetch && selectedOrg) {
      fetchProjects(selectedOrg.id);
    }
  }, [selectedOrg, fetchProjects, autoFetch]);

  const value = useMemo(
    () => ({
      organizations,
      setOrganizations,
      projects,
      setProjects,
      selectedOrg,
      setSelectedOrg,
      selectedProject,
      setSelectedProject,
      fetchOrganizations,
      fetchProjects,
    }),
    [
      organizations,
      projects,
      selectedOrg,
      selectedProject,
      fetchOrganizations,
      fetchProjects,
    ]
  );

  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>;
}

export function useProject() {
  const ctx = useContext(ProjectContext);
  if (!ctx) {
    throw new Error("useProject must be used within ProjectProvider");
  }
  return ctx;
}
