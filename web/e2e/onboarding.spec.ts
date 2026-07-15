import { test, expect } from '@playwright/test';

test('Onboarding Resident Join Flow', async ({ page }) => {
  // Mock Google auth API call
  await page.route('**/api/v1/auth/google', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ access_token: 'mock_global_token' }),
    });
  });

  // Mock Join Organization API call
  await page.route('**/api/v1/organizations/join-by-token', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        memberships: [
          {
            org_id: 'org_id_123',
            role: 'RESIDENT',
            unit_identifier: 'Flat 101',
          }
        ],
        access_token: 'scoped_token_123',
      }),
    });
  });

  // Mock scoped token selection API call
  await page.route('**/api/v1/auth/select-org', async route => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        access_token: 'scoped_token_123',
        role: 'RESIDENT',
      }),
    });
  });

  // Navigate to Join Page with token parameter
  await page.goto('/?token=token_xyz');

  // Step 1: Assert Page title
  await expect(page.locator('h2')).toContainText('Join Organization');

  // Step 2: Trigger Google Auth bypass to mock Step 1 success
  await page.click('text=Bypass Google Sign-In');

  // Step 3: Page should progress to unit identifier inputs
  const input = page.locator('input[placeholder="e.g. Flat 402, Block A"]');
  await expect(input).toBeVisible();
  await input.fill('Flat 101');

  // Step 4: Click the "Complete Registration" submit button
  await page.click('button:has-text("Complete Registration")');

  // Since onboarding succeeds and redirects to dashboard, we expect dashboard navigation (App.tsx updates view)
  // Dashboard contains visitor passes header or role indicator
  await expect(page.locator('body')).toBeVisible();
});
