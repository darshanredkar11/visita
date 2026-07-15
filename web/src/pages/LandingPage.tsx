import React from 'react';
import { Shield, Radio, Key, ArrowRight } from 'lucide-react';

interface LandingPageProps {
  onGetStarted: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onGetStarted }) => {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      {/* Navigation Header */}
      <header style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '24px 8%',
        borderBottom: '1px solid var(--border-color)',
        background: 'rgba(10, 11, 16, 0.7)',
        backdropFilter: 'blur(10px)',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            background: 'linear-gradient(135deg, var(--color-primary), #4f46e5)',
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'white',
            fontWeight: '800',
            fontSize: '1.1rem'
          }}>
            V
          </div>
          <span style={{ fontWeight: 800, fontSize: '1.25rem', letterSpacing: '-0.03em' }}>VisitorPass</span>
        </div>
        <button onClick={onGetStarted} className="btn btn-secondary" style={{ padding: '8px 18px', fontSize: '0.9rem' }}>
          Sign In
        </button>
      </header>

      {/* Hero Section */}
      <section className="animate-fade-in" style={{
        padding: '100px 8% 80px 8%',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        position: 'relative'
      }}>
        {/* Glow Accent background */}
        <div style={{
          position: 'absolute',
          top: '-50px',
          left: '50%',
          transform: 'translateX(-50%)',
          width: '500px',
          height: '500px',
          background: 'radial-gradient(circle, var(--color-primary-glow) 0%, rgba(0,0,0,0) 70%)',
          zIndex: -1,
          pointerEvents: 'none'
        }} />

        <div style={{
          background: 'rgba(255, 255, 255, 0.03)',
          border: '1px solid var(--border-color)',
          borderRadius: '30px',
          padding: '6px 16px',
          fontSize: '0.85rem',
          fontWeight: 600,
          color: 'var(--text-secondary)',
          marginBottom: '24px',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <span style={{ display: 'inline-block', width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--color-accent)' }}></span>
          V1.0.0 Stable Release
        </div>

        <h1 style={{
          fontSize: '3.5rem',
          lineHeight: 1.1,
          fontWeight: 800,
          maxWidth: '800px',
          marginBottom: '24px',
          background: 'linear-gradient(180deg, #ffffff 0%, #a5b4fc 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent'
        }}>
          Secure Visitor Access Management. Completely Offline.
        </h1>

        <p style={{
          color: 'var(--text-secondary)',
          fontSize: '1.2rem',
          maxWidth: '600px',
          marginBottom: '40px',
          lineHeight: 1.5
        }}>
          Privacy-first, cryptographically verified entry passes for housing societies, offices, and hospitals. Works even when the internet is down.
        </p>

        <button onClick={onGetStarted} className="btn btn-primary" style={{ padding: '16px 36px', fontSize: '1.05rem' }}>
          Get Started <ArrowRight size={18} />
        </button>
      </section>

      {/* Core Philosophies / Features Grid */}
      <section style={{
        padding: '60px 8% 100px 8%',
        background: 'rgba(255,255,255,0.01)',
        borderTop: '1px solid var(--border-color)'
      }}>
        <h2 style={{
          textAlign: 'center',
          fontSize: '2rem',
          marginBottom: '60px',
          color: '#ffffff'
        }}>
          Why choose VisitorPass?
        </h2>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: '30px',
          maxWidth: '1200px',
          margin: '0 auto'
        }}>
          {/* Feature 1 */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              backgroundColor: 'rgba(99, 102, 241, 0.1)',
              color: 'var(--color-primary)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Radio size={24} />
            </div>
            <h3>Offline-First</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
              Verify guest QR codes at the gate using local cryptography. Zero network latency, zero dependencies on server uptime.
            </p>
          </div>

          {/* Feature 2 */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              color: 'var(--color-accent)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Shield size={24} />
            </div>
            <h3>Security-First</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
              All passes are digitally signed using Ed25519 public-key cryptography. Non-forgeable, tamper-proof security tokens.
            </p>
          </div>

          {/* Feature 3 */}
          <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              color: 'var(--color-error)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Key size={24} />
            </div>
            <h3>Privacy-First</h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
              Visitor phone numbers are fully encrypted on devices using ChaCha20. No unauthorized access or leakage of personal contact info.
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer style={{
        marginTop: 'auto',
        padding: '30px 8%',
        borderTop: '1px solid var(--border-color)',
        textAlign: 'center',
        color: 'var(--text-muted)',
        fontSize: '0.9rem'
      }}>
        © 2026 VisitorPass. All rights reserved. Built for security-conscious communities.
      </footer>
    </div>
  );
};
