'use strict';

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
export function esc(value) { return String(value ?? '').replace(/[&<>'"]/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;' }[c])); }
export function requestId() { return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`; }
export function labelClass(key) { return String(key || '').replace(/-/g,' ').replace(/\b\w/g, (c) => c.toUpperCase()); }
export function formatDate(value) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleDateString(undefined,{dateStyle:'medium'}); }
export function toast(message, type = '') { const node=document.createElement('div'); node.className=`toast ${type}`; node.textContent=message; $('#toasts')?.append(node); setTimeout(()=>node.remove(),4200); }
export function setText(selector,value) { const node=$(selector); if (node) node.textContent=String(value ?? ''); }
