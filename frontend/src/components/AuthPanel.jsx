import { useState } from 'react';
import { api } from '../api.js';

export default function AuthPanel({ onSuccess, onClose }) {
  const [mode, setMode] = useState('login');
  const [form, setForm] = useState({ email: '', full_name: '', password: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  function update(event) {
    setForm(current => ({ ...current, [event.target.name]: event.target.value }));
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const body = mode === 'login'
        ? { email: form.email, password: form.password }
        : form;
      const result = await api(`/api/auth/${mode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      onSuccess(result.user);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy(false);
    }
  }

  return <div className="auth-backdrop" role="presentation" onMouseDown={event => event.target === event.currentTarget && onClose()}>
    <section className="auth-card" role="dialog" aria-modal="true" aria-labelledby="auth-title">
      <button className="auth-close" type="button" aria-label="Đóng cửa sổ đăng nhập" onClick={onClose}>×</button>
      <p className="eyebrow">{mode === 'login' ? 'CHÀO MỪNG TRỞ LẠI' : 'TẠO TÀI KHOẢN MỚI'}</p>
      <h2 id="auth-title">{mode === 'login' ? 'Đăng nhập' : 'Đăng ký tài khoản'}</h2>
      <p className="auth-intro">{mode === 'login' ? 'Đăng nhập để lưu và xem lại các lần kiểm tra.' : 'Tài khoản đăng ký mới được tạo với vai trò sinh viên.'}</p>
      <form onSubmit={submit}>
        {mode === 'register' && <label>Họ và tên<input name="full_name" value={form.full_name} onChange={update} required maxLength={120} autoComplete="name" /></label>}
        <label>Email<input name="email" type="email" value={form.email} onChange={update} required maxLength={254} autoComplete="email" /></label>
        <label>Mật khẩu<input name="password" type="password" value={form.password} onChange={update} required maxLength={200} minLength={10} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} /></label>
        {mode === 'register' && <p className="field-note">Mật khẩu tối thiểu 10 ký tự, không được trùng email.</p>}
        {error && <p className="auth-error" role="alert">{error}</p>}
        <button className="button primary auth-submit" disabled={busy} type="submit">{busy ? 'Đang xử lý…' : mode === 'login' ? 'Đăng nhập' : 'Tạo tài khoản'} <span aria-hidden="true">→</span></button>
      </form>
      <button className="auth-switch" type="button" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); }}>
        {mode === 'login' ? 'Chưa có tài khoản? Đăng ký' : 'Đã có tài khoản? Đăng nhập'}
      </button>
    </section>
  </div>;
}
