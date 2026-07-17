import { useEffect, useRef, useState } from 'react';
import { LandingPage } from './pages/LandingPage';
import { JoinPage } from './pages/JoinPage';
import { GoogleLoginButton } from './components/GoogleLoginButton';
import { LogOut, Plus, Share2, Clipboard, Users, CheckCircle, Clock } from 'lucide-react';
import './App.css';

interface User {
  id:        string;
  email:     string;
  full_name: string;
}

interface Membership {
  org_id:          string;
  org_name:        String;
  role:            string;
  unit_identifier: string;
}

function App() {
  // Read invite token from URL search query (e.g. ?token=INV-XXXXXX)
  const queryParams = new URLSearchParams(window.location.search);
  const inviteToken = queryParams.get('token') || '';

  // Auth States
  const [token, setToken] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(localStorage.getItem('vp_role'));
  const [orgId, setOrgId] = useState<string | null>(localStorage.getItem('vp_org_id'));
  const [user, setUser] = useState<User | null>(JSON.parse(localStorage.getItem('vp_user') || 'null'));
  const [memberships, setMemberships] = useState<Membership[]>(JSON.parse(localStorage.getItem('vp_memberships') || '[]'));

  // Routing State
  const [page, setPage] = useState<'landing' | 'login' | 'join' | 'dashboard'>(
    token && orgId ? 'dashboard' : inviteToken ? 'join' : 'landing'
  );

  // Form States (Pass Creation)
  const [visitorName, setVisitorName] = useState('');
  const [visitorPhone, setVisitorPhone] = useState('');
  const [passDuration, setPassDuration] = useState('6'); // 6 hours default
  const [createdPass, setCreatedPass] = useState<{ pass_number: string; share_url: string } | null>(null);
  const [loadingPass, setLoadingPass] = useState(false);
  const [errorPass, setErrorPass] = useState<string | null>(null);

  // Secretary Invite QR States
  const [inviteUrl, setInviteUrl] = useState<string | null>(null);
  const [loadingInvite, setLoadingInvite] = useState(false);

  // The access token lives only in memory (never persisted), so a page
  // refresh always loses it even though the backend's HttpOnly refresh
  // cookie is still valid. If we previously scoped into an org (orgId
  // survived in localStorage -- fine to persist, it isn't a secret),
  // silently try to reacquire an access token via that cookie before
  // forcing the user back through the full login flow. Guarded by a ref
  // (not just the empty dep array) because StrictMode's dev-only
  // double-invoke would otherwise fire this twice concurrently, racing
  // two rotations of the same refresh token against each other.
  const attemptedSilentRefresh = useRef(false);
  useEffect(() => {
    if (token || !orgId || attemptedSilentRefresh.current) return;
    attemptedSilentRefresh.current = true;

    (async () => {
      try {
        const res = await fetch('/api/v1/auth/refresh', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        });
        if (!res.ok) throw new Error('refresh failed');
        const data = await res.json();
        setToken(data.access_token);
        setRole(data.role);
        localStorage.setItem('vp_role', data.role);
        setPage('dashboard');
      } catch {
        // No valid refresh session (expired/revoked/never existed) --
        // fall back to a clean logged-out state instead of showing a
        // stale dashboard shell with no way to authenticate API calls.
        localStorage.clear();
        setRole(null);
        setOrgId(null);
        setUser(null);
        setMemberships([]);
        setPage('landing');
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleLoginSuccess = async (idToken: string) => {
    try {
      const res = await fetch('/api/v1/auth/google', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id_token: idToken }),
      });

      if (!res.ok) throw new Error('Authentication failed');
      const data = await res.json();

      setUser(data.user);
      setMemberships(data.memberships);
      localStorage.setItem('vp_user', JSON.stringify(data.user));
      localStorage.setItem('vp_memberships', JSON.stringify(data.memberships));

      if (data.access_token) {
        // Scoped token (exactly 1 membership)
        setToken(data.access_token);
        setRole(data.role);
        const activeOrg = data.memberships[0].org_id;
        setOrgId(activeOrg);
        localStorage.setItem('vp_role', data.role);
        localStorage.setItem('vp_org_id', activeOrg);
        setPage('dashboard');
      } else {
        // Global token (0 or >1 memberships)
        setToken(data.access_token); // fallback token
        if (data.memberships.length > 0) {
          // Force select org screen by staying in login but prompting selection
          setRole(null);
          setOrgId(null);
        } else {
          // No memberships, prompt join
          setPage('landing');
          alert('You do not belong to any Organization yet. Please ask your building secretary for a Join Link/QR.');
        }
      }
    } catch (err) {
      alert('Failed to log in: Authentication server unreachable');
    }
  };

  const handleJoinSuccess = (newMemberships: any[], activeToken: string, activeRole: string, activeOrgId: string) => {
    setMemberships(newMemberships);
    setToken(activeToken);
    setRole(activeRole);
    setOrgId(activeOrgId);

    localStorage.setItem('vp_memberships', JSON.stringify(newMemberships));
    localStorage.setItem('vp_role', activeRole);
    localStorage.setItem('vp_org_id', activeOrgId);

    // Clear search query param cleanly without reloading
    window.history.pushState({}, document.title, window.location.pathname);
    setPage('dashboard');
  };

  const handleSelectOrg = async (selectedOrgId: string) => {
    const fallbackToken = token;
    if (!fallbackToken) return;

    try {
      const res = await fetch('/api/v1/auth/select-org', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${fallbackToken}`
        },
        body: JSON.stringify({ org_id: selectedOrgId }),
      });

      if (!res.ok) throw new Error('Failed to select organization');
      const data = await res.json();

      setToken(data.access_token);
      setRole(data.role);
      setOrgId(selectedOrgId);

      localStorage.setItem('vp_role', data.role);
      localStorage.setItem('vp_org_id', selectedOrgId);
      setPage('dashboard');
    } catch (err) {
      alert('Failed to scope session');
    }
  };

  const handleLogout = () => {
    // Best-effort, fire-and-forget: revoke the session server-side and
    // clear the HttpOnly cookie. The cookie is unreachable from JS
    // (that's the point), so there is no client-side equivalent of
    // `localStorage.clear()` for it -- the backend must be told to drop
    // it, or a stolen/leaked cookie would remain valid for its full
    // 30-day lifetime after the user believes they've logged out. Not
    // awaited: logout should feel instant, and there's nothing useful to
    // do differently if this request fails.
    fetch('/api/v1/auth/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    }).catch(() => {});

    localStorage.clear();
    setToken(null);
    setRole(null);
    setOrgId(null);
    setUser(null);
    setMemberships([]);
    setCreatedPass(null);
    setInviteUrl(null);
    setPage('landing');
  };

  const handleCreatePass = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !orgId) return;

    setLoadingPass(true);
    setErrorPass(null);
    setCreatedPass(null);

    const validFrom = new Date().toISOString();
    const validUntil = new Date(Date.now() + parseInt(passDuration) * 60 * 60 * 1000).toISOString();

    try {
      const res = await fetch(`/api/v1/organizations/${orgId}/passes`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          visitor_name: visitorName.trim(),
          visitor_phone: visitorPhone.trim(),
          valid_from: validFrom,
          valid_until: validUntil,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to create pass');
      }

      setCreatedPass({
        pass_number: data.pass_number,
        share_url: `${window.location.origin}/v/${data.pass_number}`,
      });
      setVisitorName('');
      setVisitorPhone('');
    } catch (err: any) {
      setErrorPass(err.message || 'Verification error');
    } finally {
      setLoadingPass(false);
    }
  };

  const handleGetInviteLink = async () => {
    if (!token || !orgId) return;
    setLoadingInvite(true);
    try {
      const res = await fetch(`/api/v1/organizations/${orgId}/join-token`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await res.json();
      if (res.ok) {
        setInviteUrl(data.url);
      }
    } catch (err) {
      alert('Failed to load join link');
    } finally {
      setLoadingInvite(false);
    }
  };

  // Get active organization name
  const activeOrgName = memberships.find((m) => m.org_id === orgId)?.org_name || 'Organization';
  const activeUnit = memberships.find((m) => m.org_id === orgId)?.unit_identifier || '';

  return (
    <div className="app-container">
      {/* 1. LANDING PAGE */}
      {page === 'landing' && (
        <LandingPage onGetStarted={() => setPage(inviteToken ? 'join' : 'login')} />
      )}

      {/* 2. LOGIN PAGE */}
      {page === 'login' && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifySelf: 'center', justifyContent: 'center', padding: '20px' }}>
          <div className="glass-card animate-fade-in" style={{ width: '100%', maxWidth: '400px', textAlign: 'center' }}>
            <h2 style={{ fontSize: '1.75rem', marginBottom: '10px' }}>Welcome back</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', marginBottom: '32px' }}>
              Sign in with Google to access your dashboard.
            </p>
            <GoogleLoginButton onSuccess={handleLoginSuccess} onFailure={(err) => alert(err)} />
            
            {/* If user logged in but hasn't selected org */}
            {memberships.length > 1 && !orgId && (
              <div style={{ borderTop: '1px solid var(--border-color)', marginTop: '24px', paddingTop: '24px' }}>
                <h3 style={{ fontSize: '1rem', marginBottom: '14px', color: 'var(--color-warning)' }}>
                  Select Flat / Workspace
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {memberships.map((m) => (
                    <button
                      key={m.org_id}
                      onClick={() => handleSelectOrg(m.org_id)}
                      className="btn btn-secondary"
                      style={{ justifyContent: 'space-between', width: '100%', fontSize: '0.85rem' }}
                    >
                      <span>{m.org_name}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{m.unit_identifier}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
            
            <button
              onClick={() => setPage('landing')}
              className="btn btn-secondary"
              style={{ border: 'none', background: 'transparent', color: 'var(--text-secondary)', marginTop: '20px' }}
            >
              Back to Home
            </button>
          </div>
        </div>
      )}

      {/* 3. JOIN WIZARD PAGE */}
      {page === 'join' && (
        <JoinPage inviteToken={inviteToken} onJoinSuccess={handleJoinSuccess} />
      )}

      {/* 4. DASHBOARD PAGE */}
      {page === 'dashboard' && token && orgId && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {/* Header */}
          <header style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '16px 8%',
            borderBottom: '1px solid var(--border-color)',
            background: 'var(--bg-surface)'
          }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                {activeOrgName.toUpperCase()}
              </span>
              <span style={{ fontSize: '1.15rem', fontWeight: 800 }}>
                {activeUnit ? `${activeUnit}` : 'Dashboard'}
              </span>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              {/* Organization Switcher if they have multiple memberships */}
              {memberships.length > 1 && (
                <select
                  value={orgId}
                  onChange={(e) => handleSelectOrg(e.target.value)}
                  style={{
                    backgroundColor: 'rgba(255,255,255,0.05)',
                    border: '1px solid var(--border-color)',
                    color: 'white',
                    padding: '6px 12px',
                    borderRadius: '8px',
                    fontFamily: 'var(--font-family)',
                    fontSize: '0.85rem',
                    outline: 'none'
                  }}
                >
                  {memberships.map((m) => (
                    <option key={m.org_id} value={m.org_id} style={{ backgroundColor: 'var(--bg-surface)' }}>
                      {m.org_name} ({m.unit_identifier})
                    </option>
                  ))}
                </select>
              )}

              {user && (
                <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
                  Hi, {user.full_name}
                </span>
              )}

              <button
                onClick={handleLogout}
                className="btn btn-secondary"
                style={{ padding: '8px 14px', borderRadius: '8px' }}
              >
                <LogOut size={16} /> Logout
              </button>
            </div>
          </header>

          {/* Main Dashboard Content */}
          <main style={{ flex: 1, padding: '40px 8%', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '30px', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
            
            {/* Left: Quick Actions / Invite Form */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }}>
              <div className="glass-card">
                <h3 style={{ fontSize: '1.2rem', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Plus size={20} color="var(--color-primary)" /> Invite Guest
                </h3>
                
                {errorPass && (
                  <div style={{ color: 'var(--color-error)', fontSize: '0.85rem', marginBottom: '16px' }}>
                    {errorPass}
                  </div>
                )}

                <form onSubmit={handleCreatePass} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px', fontWeight: 600 }}>
                      Guest Full Name
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. John Doe"
                      value={visitorName}
                      onChange={(e) => setVisitorName(e.target.value)}
                      className="input-field"
                      required
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px', fontWeight: 600 }}>
                      Guest Phone Number
                    </label>
                    <input
                      type="tel"
                      placeholder="e.g. +91 98765 43210"
                      value={visitorPhone}
                      onChange={(e) => setVisitorPhone(e.target.value)}
                      className="input-field"
                      required
                    />
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px', fontWeight: 600 }}>
                      Pass Validity Duration
                    </label>
                    <select
                      value={passDuration}
                      onChange={(e) => setPassDuration(e.target.value)}
                      className="input-field"
                      style={{ appearance: 'none' }}
                    >
                      <option value="2" style={{ backgroundColor: 'var(--bg-surface)' }}>2 Hours</option>
                      <option value="6" style={{ backgroundColor: 'var(--bg-surface)' }}>6 Hours</option>
                      <option value="12" style={{ backgroundColor: 'var(--bg-surface)' }}>12 Hours</option>
                      <option value="24" style={{ backgroundColor: 'var(--bg-surface)' }}>24 Hours</option>
                    </select>
                  </div>

                  <button type="submit" className="btn btn-primary" style={{ width: '100%', marginTop: '10px' }} disabled={loadingPass}>
                    {loadingPass ? 'Generating...' : 'Create Invite Link'}
                  </button>
                </form>
              </div>

              {/* Secretary Group Invite Link Generation Block */}
              {role === 'ORG_ADMIN' && (
                <div className="glass-card" style={{ borderLeft: '4px solid var(--color-accent)' }}>
                  <h3 style={{ fontSize: '1.2rem', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Users size={20} color="var(--color-accent)" /> Group Onboarding QR
                  </h3>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '20px' }}>
                    Generate a join link/QR code for residents to scan and instantly register their apartments.
                  </p>
                  
                  {inviteUrl ? (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
                      <img
                        src={`https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(inviteUrl)}`}
                        alt="Join QR"
                        style={{ border: '4px solid white', borderRadius: '8px' }}
                      />
                      <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
                        <input
                          type="text"
                          value={inviteUrl}
                          readOnly
                          className="input-field"
                          style={{ fontSize: '0.75rem', padding: '8px 12px' }}
                        />
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(inviteUrl);
                            alert('Onboarding URL copied to clipboard!');
                          }}
                          className="btn btn-secondary"
                          style={{ padding: '8px' }}
                        >
                          <Clipboard size={16} />
                        </button>
                      </div>
                      <button onClick={handleGetInviteLink} className="btn btn-secondary" style={{ width: '100%', fontSize: '0.8rem' }} disabled={loadingInvite}>
                        Rotate Token
                      </button>
                    </div>
                  ) : (
                    <button onClick={handleGetInviteLink} className="btn btn-secondary" style={{ width: '100%' }} disabled={loadingInvite}>
                      {loadingInvite ? 'Generating...' : 'Generate Onboarding QR'}
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Right: Guest Pass Display Panel */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '30px' }}>
              {createdPass ? (
                <div className="glass-card animate-fade-in" style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '24px',
                  border: '1px solid var(--color-primary)',
                  boxShadow: '0 4px 30px var(--color-primary-glow)'
                }}>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ color: 'var(--color-success)', fontWeight: 'bold', fontSize: '0.9rem', marginBottom: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                      <CheckCircle size={16} /> PASS GENERATED SUCCESSFULLY
                    </div>
                    <span style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '0.05em', color: 'var(--color-primary)' }}>
                      {createdPass.pass_number}
                    </span>
                  </div>

                  <img
                    src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(createdPass.share_url)}`}
                    alt="Pass QR"
                    style={{ border: '8px solid white', borderRadius: '12px', boxShadow: '0 4px 20px rgba(0,0,0,0.3)' }}
                  />

                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', textAlign: 'center', maxWidth: '300px' }}>
                    Guests can scan this QR at the gate to get validated offline.
                  </p>

                  <div style={{ display: 'flex', gap: '10px', width: '100%' }}>
                    <input
                      type="text"
                      value={createdPass.share_url}
                      readOnly
                      className="input-field"
                      style={{ fontSize: '0.8rem', padding: '10px 14px' }}
                    />
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(createdPass.share_url);
                        alert('Visitor share link copied to clipboard!');
                      }}
                      className="btn btn-primary"
                      style={{ padding: '12px' }}
                    >
                      <Share2 size={18} />
                    </button>
                  </div>
                  
                  <a
                    href={createdPass.share_url}
                    target="_blank"
                    rel="noreferrer"
                    style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-primary)', display: 'flex', alignItems: 'center', gap: '4px' }}
                  >
                    Open Share Page &rarr;
                  </a>
                </div>
              ) : (
                <div className="glass-card" style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: '60px 40px',
                  color: 'var(--text-muted)',
                  textAlign: 'center',
                  border: '1px dashed var(--border-color)',
                  background: 'transparent'
                }}>
                  <Clock size={48} style={{ marginBottom: '16px', opacity: 0.5 }} />
                  <h4 style={{ color: 'var(--text-secondary)', marginBottom: '8px' }}>No Pass Displayed</h4>
                  <p style={{ fontSize: '0.9rem', maxWidth: '260px' }}>
                    Fill out the "Invite Guest" form on the left to generate a cryptographically signed guest QR code.
                  </p>
                </div>
              )}
            </div>

          </main>
        </div>
      )}
    </div>
  );
}

export default App;
