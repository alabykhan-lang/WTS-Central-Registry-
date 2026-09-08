'use strict';

export const state = { context: null, route: 'dashboard', cache: new Map(), request: 0 };
export function resetCache() { state.cache.clear(); }
export function hasCapability(code) {
  const list = state.context?.entitlements?.capabilities || [];
  return list.includes('*') || list.includes(code);
}
export function scopeText() {
  const e = state.context?.entitlements || {};
  if (e.capabilities?.includes('students.school.read')) return 'School-wide student and staff scope';
  if (e.stageScopes?.length) return `Stage scope: ${e.stageScopes.join(', ')}`;
  if (e.classScopes?.length) return `Allocated class scope: ${e.classScopes.join(', ')}`;
  return 'Profile-only scope until a class or portfolio is assigned';
}
