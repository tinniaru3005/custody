import type { ActionExplain, GuardDecision, Verdict } from "../api/types";

export interface Flip {
  actionId: string;
  actionType: string;
  before: Verdict;
  beforeTriggered: string[];
  after: GuardDecision;
  explain?: ActionExplain; // fetched after the approval: shows the new graph relationships
  knownBefore: string[]; // approval relationships already on the action before approving
}

export const relKey = (a: { id: string; relation: string; datum_id?: string }) =>
  `${a.id}|${a.relation}|${a.datum_id ?? ""}`;
