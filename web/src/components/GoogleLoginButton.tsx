import React, { useEffect, useState } from 'react';

// Declare google global types from Google Identity Services SDK
declare global {
  interface Window {
    google?: {
      accounts: {
        id: {
          initialize: (config: any) => void;
          renderButton: (parent: HTMLElement | null, options: any) => void;
          prompt: () => void;
        };
      };
    };
  }
}

interface GoogleLoginButtonProps {
  onSuccess: (idToken: string) => void;
  onFailure: (error: string) => void;
}

export const GoogleLoginButton: React.FC<GoogleLoginButtonProps> = ({ onSuccess, onFailure }) => {
  const [isSdkLoaded, setIsSdkLoaded] = useState(false);
  const [mockEmail, setMockEmail] = useState('resident@visitorpass.app');
  const [showDevLogin, setShowDevLogin] = useState(false);

  // In production, we'd load this from an environment variable.
  // Using a mock client ID for setup since the backend allows dev bypass.
  const GOOGLE_CLIENT_ID = '1234567890-mockclientid.apps.googleusercontent.com';

  useEffect(() => {
    // Poll to check if window.google has loaded from the index.html script tag
    const interval = setInterval(() => {
      if (window.google) {
        setIsSdkLoaded(true);
        clearInterval(interval);
      }
    }, 100);

    // If it's running in development, show the offline dev login bypass option
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      setShowDevLogin(true);
    }

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!isSdkLoaded || !window.google) return;

    try {
      window.google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: (response: any) => {
          if (response.credential) {
            onSuccess(response.credential);
          } else {
            onFailure('No credential returned from Google login');
          }
        },
      });

      const btnContainer = document.getElementById('google-signin-btn-container');
      if (btnContainer) {
        window.google.accounts.id.renderButton(btnContainer, {
          theme: 'dark',
          size: 'large',
          width: 320,
          text: 'signin_with',
          shape: 'pill',
        });
      }
    } catch (err: any) {
      console.error('Google SDK Initialization Error', err);
      onFailure(err.message || 'SDK failed to initialize');
    }
  }, [isSdkLoaded, onSuccess, onFailure]);

  const handleDevSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mockEmail.trim().includes('@')) {
      // Dev bypass prefix detected by the backend
      onSuccess(`mock_${mockEmail.trim()}`);
    } else {
      onFailure('Please enter a valid email address');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px', width: '100%' }}>
      {/* Official Google sign-in container */}
      <div id="google-signin-btn-container" style={{ minHeight: '44px' }}>
        {!isSdkLoaded && (
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
            Loading secure authentication...
          </div>
        )}
      </div>

      {/* Development offline login override block */}
      {showDevLogin && (
        <div style={{
          width: '320px',
          padding: '20px',
          borderRadius: 'var(--border-radius-md)',
          border: '1px dashed var(--border-color)',
          background: 'rgba(255, 255, 255, 0.01)',
          marginTop: '10px'
        }}>
          <div style={{
            fontSize: '0.8rem',
            color: 'var(--color-warning)',
            fontWeight: '600',
            textAlign: 'center',
            marginBottom: '12px',
            textTransform: 'uppercase',
            letterSpacing: '0.05em'
          }}>
            🔌 Offline Developer Bypass
          </div>
          <form onSubmit={handleDevSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <input
              type="email"
              value={mockEmail}
              onChange={(e) => setMockEmail(e.target.value)}
              placeholder="mock_user@email.com"
              className="input-field"
              style={{ fontSize: '0.85rem', padding: '10px 14px' }}
              required
            />
            <button type="submit" className="btn btn-secondary" style={{ padding: '8px 16px', fontSize: '0.85rem' }}>
              Bypass Google Sign-In
            </button>
          </form>
        </div>
      )}
    </div>
  );
};
