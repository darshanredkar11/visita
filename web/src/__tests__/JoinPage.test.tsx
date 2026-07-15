import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { JoinPage } from '../pages/JoinPage';

// Mock Lucide icons to avoid rendering complexities in jsdom
vi.mock('lucide-react', () => ({
  Home: () => <span data-testid="icon-home" />,
  AlertTriangle: () => <span data-testid="icon-alert" />
}));

describe('JoinPage Onboarding Wizard', () => {
  it('renders welcome screen with google auth instructions', () => {
    const handleSuccess = vi.fn();
    render(<JoinPage inviteToken="token_xyz" onJoinSuccess={handleSuccess} />);

    // Renders the main Join Organization card header
    expect(screen.getByText(/Join Organization/i)).toBeDefined();
    expect(screen.getByText(/Sign in with Google to authenticate/i)).toBeDefined();
  });

  it('renders offline developer bypass form', () => {
    const handleSuccess = vi.fn();
    render(<JoinPage inviteToken="token_xyz" onJoinSuccess={handleSuccess} />);

    expect(screen.getByText(/Offline Developer Bypass/i)).toBeDefined();
    expect(screen.getByText(/Bypass Google Sign-In/i)).toBeDefined();
  });
});
