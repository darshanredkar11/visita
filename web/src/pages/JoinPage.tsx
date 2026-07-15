import React, { useState, useEffect } from 'react';
import { GoogleLoginButton } from '../components/GoogleLoginButton';
import { Home, AlertTriangle } from 'lucide-react';

interface JoinPageProps {
  inviteToken: string;
  onJoinSuccess: (memberships: any[], activeToken: string, activeRole: string, activeOrgId: string) => void;
}

export const JoinPage: React.FC<JoinPageProps> = ({ inviteToken, onJoinSuccess }) => {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [userIdToken, setUserIdToken] = useState<string | null>(null);
  const [unitIdentifier, setUnitIdentifier] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);


  // Auto-verify invite token when Google login completes (Step 2)
  useEffect(() => {
    if (step === 2 && userIdToken) {
      // In a production app, we would make a GET verify endpoint to show the Org details
      // before they fill in their unit. For V1 simplicity, we will let them enter their flat
      // number and perform the join + validation atomically in Step 3.
      // We simulate org check here or just proceed.
      setStep(3);
    }
  }, [step, userIdToken]);

  const handleGoogleSuccess = async (idToken: string) => {
    setLoading(true);
    setError(null);
    try {
      // 1. Authenticate with backend using Google Token
      const res = await fetch('/api/v1/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id_token: idToken }),
      });

      if (!res.ok) {
        throw new Error('Failed to authenticate with VisitorPass backend');
      }

      const data = await res.json();
      
      // Save global user credentials
      setUserIdToken(data.access_token);
      setStep(2);
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleFailure = (errStr: string) => {
    setError(errStr);
  };

  const handleJoinSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userIdToken || unitIdentifier.trim() === '') return;

    setLoading(true);
    setError(null);
    try {
      // 2. Onboard to Org using Group Join Token
      const res = await fetch('/api/v1/organizations/join-by-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${userIdToken}`
        },
        body: JSON.stringify({
          token: inviteToken,
          unit_identifier: unitIdentifier.trim(),
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to join organization. Invite link may be invalid or expired.');
      }

      // Find the newly joined membership
      const memberships = data.memberships || [];
      // Request a scoped token for the newly joined org
      // For simplicity, find the first or last active membership
      if (memberships.length === 0) {
        throw new Error('No active memberships found after onboarding.');
      }

      const activeMember = memberships[memberships.length - 1]; // latest joined

      // Request a scoped token
      const tokenRes = await fetch('/api/v1/auth/select-org', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${userIdToken}`
        },
        body: JSON.stringify({ org_id: activeMember.org_id }),
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok) {
        throw new Error('Failed to acquire scoped organization token');
      }

      // Successful onboarding! Return details to parent App
      onJoinSuccess(memberships, tokenData.access_token, tokenData.role, activeMember.org_id);
    } catch (err: any) {
      setError(err.message || 'Failed to complete registration');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      flex: 1,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '40px 20px',
      position: 'relative'
    }}>
      {/* Background glow */}
      <div style={{
        position: 'absolute',
        width: '400px',
        height: '400px',
        background: 'radial-gradient(circle, var(--color-primary-glow) 0%, rgba(0,0,0,0) 70%)',
        zIndex: -1,
        pointerEvents: 'none'
      }} />

      <div className="glass-card animate-fade-in" style={{ width: '100%', maxWidth: '440px' }}>
        {/* Step Indicator Header */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginBottom: '32px' }}>
          <div style={{
            width: '24px',
            height: '24px',
            borderRadius: '50%',
            backgroundColor: step >= 1 ? 'var(--color-primary)' : 'var(--bg-base)',
            color: step >= 1 ? 'white' : 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.8rem',
            fontWeight: 'bold',
            border: step >= 1 ? 'none' : '1px solid var(--border-color)'
          }}>1</div>
          <div style={{ width: '40px', height: '1px', backgroundColor: 'var(--border-color)', alignSelf: 'center' }} />
          <div style={{
            width: '24px',
            height: '24px',
            borderRadius: '50%',
            backgroundColor: step >= 3 ? 'var(--color-primary)' : 'var(--bg-base)',
            color: step >= 3 ? 'white' : 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '0.8rem',
            fontWeight: 'bold',
            border: step >= 3 ? 'none' : '1px solid var(--border-color)'
          }}>2</div>
        </div>

        {/* Error Alert */}
        {error && (
          <div style={{
            padding: '16px',
            borderRadius: 'var(--border-radius-md)',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            color: 'var(--color-error)',
            fontSize: '0.9rem',
            display: 'flex',
            gap: '10px',
            marginBottom: '24px'
          }}>
            <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>{error}</div>
          </div>
        )}

        {/* STEP 1: Google Login */}
        {step === 1 && (
          <div style={{ textAlign: 'center' }}>
            <h2 style={{ fontSize: '1.5rem', marginBottom: '12px' }}>Join Organization</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', marginBottom: '32px' }}>
              Sign in with Google to authenticate and link your account safely.
            </p>
            <GoogleLoginButton onSuccess={handleGoogleSuccess} onFailure={handleGoogleFailure} />
          </div>
        )}

        {/* STEP 2: Loading State */}
        {step === 2 && (
          <div style={{ textAlign: 'center', padding: '20px 0' }}>
            <h2 style={{ fontSize: '1.3rem', marginBottom: '12px' }}>Verifying Identity...</h2>
            <div className="spinner" style={{ margin: '0 auto 20px auto' }}></div>
          </div>
        )}

        {/* STEP 3: Enter Unit Details */}
        {step === 3 && (
          <div>
            <div style={{ textAlign: 'center', marginBottom: '30px' }}>
              <div style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: '48px',
                height: '48px',
                borderRadius: '12px',
                backgroundColor: 'rgba(99, 102, 241, 0.1)',
                color: 'var(--color-primary)',
                marginBottom: '16px'
              }}>
                <Home size={24} />
              </div>
              <h2 style={{ fontSize: '1.5rem', marginBottom: '8px' }}>Registration Details</h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                You are joining the organization. Please enter your unit or flat info below.
              </p>
            </div>

            <form onSubmit={handleJoinSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div>
                <label style={{
                  display: 'block',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: 'var(--text-secondary)',
                  marginBottom: '8px'
                }}>
                  Flat / Apartment / Desk / Unit
                </label>
                <input
                  type="text"
                  placeholder="e.g. Flat 402, Block A"
                  value={unitIdentifier}
                  onChange={(e) => setUnitIdentifier(e.target.value)}
                  className="input-field"
                  required
                  disabled={loading}
                />
              </div>

              <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
                {loading ? 'Registering...' : 'Complete Registration'}
              </button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
};
