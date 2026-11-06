import { AlertCircle, ArrowUpRight, Info, LoaderCircle, Plus, RefreshCw, X } from 'lucide-react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';

export function PageHeading({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description?: string; actions?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{actions && <div className="page-actions">{actions}</div>}</div>;
}
export function Button({ children, variant = 'primary', className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger' }) {
  return <button className={`button button-${variant} ${className}`.trim()} {...props}>{children}</button>;
}
export function LoadingState({ label = 'Loading secure workspace' }: { label?: string }) {
  return <div className="state-card"><LoaderCircle className="spin" size={22} /><span>{label}</span></div>;
}
export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return <div className="state-card state-error"><AlertCircle size={20} /><div><strong>Couldn’t load this view</strong><p>{message}</p>{onRetry && <Button variant="secondary" onClick={onRetry}><RefreshCw size={14} />Try again</Button>}</div></div>;
}
export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return <div className="empty-state"><div className="empty-orbit"><span /></div><h3>{title}</h3><p>{body}</p>{action}</div>;
}
export function UnavailableState({ title, detail, endpoint }: { title: string; detail: string; endpoint?: string }) {
  return <div className="unavailable-card"><div className="unavailable-icon"><Info size={19} /></div><div><div className="unavailable-top"><h3>{title}</h3><span className="tag tag-muted">Not connected</span></div><p>{detail}</p>{endpoint && <div className="endpoint-note"><code>{endpoint}</code><span>API Gateway route required</span><ArrowUpRight size={13} /></div>}</div></div>;
}
export function MetricCard({ label, value, note, icon, accent = 'blue', unavailable = false }: { label: string; value: string | number; note: string; icon: ReactNode; accent?: string; unavailable?: boolean }) {
  return <article className={`metric-card accent-${accent}`}><div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div><div className={`metric-value ${unavailable ? 'muted-value' : ''}`}>{value}</div><div className="metric-note">{note}</div></article>;
}
export function StatusBadge({ status }: { status: string }) {
  const kind = status.toLowerCase().replaceAll('_', '-');
  return <span className={`status-badge status-${kind}`}><i />{status.replaceAll('_', ' ')}</span>;
}
export function Modal({ title, subtitle, onClose, children, wide = false }: { title: string; subtitle?: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className={`modal-card ${wide ? 'modal-wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby="modal-title"><div className="modal-heading"><div><h2 id="modal-title">{title}</h2>{subtitle && <p>{subtitle}</p>}</div><button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={19} /></button></div>{children}</section></div>;
}
export function AddButton({ children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <Button {...props}><Plus size={16} />{children}</Button>;
}
export function FormField({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="form-field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}
export function TableBlank({ columns, title, detail }: { columns: number; title: string; detail: string }) {
  return <tr><td colSpan={columns}><EmptyState title={title} body={detail} /></td></tr>;
}
