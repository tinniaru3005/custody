import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type { PlannerName } from "./types";

export const keys = {
  all: ["custody"] as const,
  health: ["custody", "health"] as const,
  overview: ["custody", "overview"] as const,
  graph: (decisions: boolean) => ["custody", "graph", decisions] as const,
  actions: ["custody", "actions"] as const,
  explain: (id: string) => ["custody", "explain", id] as const,
  approvals: ["custody", "approvals"] as const,
  metrics: ["custody", "metrics"] as const,
  demo: ["custody", "demo"] as const,
  warden: ["custody", "warden"] as const,
  worlds: ["custody", "worlds"] as const,
  readjudications: ["custody", "readjudications"] as const,
  chokepoints: (id: string) => ["custody", "chokepoints", id] as const,
  datum: (id: string) => ["custody", "datum", id] as const,
};

export const useHealth = () =>
  useQuery({ queryKey: keys.health, queryFn: api.health, refetchInterval: 15000, retry: 0 });
/** True when the backend runs in public-demo mode (read-only; only "Reset Demo" writes). */
export function usePublicDemo(): boolean {
  return useHealth().data?.public_demo === true;
}
export const useOverview = () =>
  useQuery({ queryKey: keys.overview, queryFn: () => api.overview() });
export const useGraph = (includeDecisions = false) =>
  useQuery({
    queryKey: keys.graph(includeDecisions),
    queryFn: () => api.graph(undefined, includeDecisions),
  });
export const useActions = () => useQuery({ queryKey: keys.actions, queryFn: () => api.actions() });
export const useExplain = (id: string | undefined) =>
  useQuery({ queryKey: keys.explain(id ?? ""), queryFn: () => api.explain(id!), enabled: !!id });
export const useApprovals = () =>
  useQuery({ queryKey: keys.approvals, queryFn: () => api.approvals() });
export const useMetrics = () => useQuery({ queryKey: keys.metrics, queryFn: () => api.metrics() });
export const useDemo = () => useQuery({ queryKey: keys.demo, queryFn: () => api.demo() });
export const useWardenRun = () =>
  useQuery({ queryKey: keys.warden, queryFn: () => api.wardenRun() });
export const useDatum = (id: string | undefined) =>
  useQuery({ queryKey: keys.datum(id ?? ""), queryFn: () => api.datum(id!), enabled: !!id });

function useInvalidateAll() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries({ queryKey: keys.all });
}

export const useInfluence = () =>
  useQuery({ queryKey: ["custody", "influence"], queryFn: () => api.influence() });
export const useWorlds = () => useQuery({ queryKey: keys.worlds, queryFn: () => api.worlds() });
export const useReadjudications = () =>
  useQuery({ queryKey: keys.readjudications, queryFn: () => api.readjudications() });
export const useChokepoints = (id: string, enabled: boolean) =>
  useQuery({ queryKey: keys.chokepoints(id), queryFn: () => api.chokepoints(id), enabled });

export function useBuildWorlds() {
  const invalidate = useInvalidateAll();
  return useMutation({ mutationFn: () => api.buildWorlds(), onSuccess: invalidate });
}

export function useRunAttack() {
  const invalidate = useInvalidateAll();
  return useMutation({ mutationFn: () => api.runAttack(), onSuccess: invalidate });
}

export function useReset() {
  const invalidate = useInvalidateAll();
  return useMutation({ mutationFn: () => api.reset(), onSuccess: invalidate });
}

export function useInvestigate() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (v: { request: string; planner: PlannerName }) =>
      api.investigate(v.request, v.planner),
    onSuccess: invalidate,
  });
}

export function useApprove() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (v: { actionId: string; approver: string; reason?: string }) =>
      api.approve(v.actionId, v.approver, v.reason),
    onSuccess: invalidate,
  });
}

export function useReject() {
  const invalidate = useInvalidateAll();
  return useMutation({
    mutationFn: (v: { actionId: string; approver: string; reason?: string }) =>
      api.reject(v.actionId, v.approver, v.reason),
    onSuccess: invalidate,
  });
}

export function useSendDisclosure() {
  const invalidate = useInvalidateAll();
  return useMutation({ mutationFn: (id: string) => api.sendDisclosure(id), onSuccess: invalidate });
}
