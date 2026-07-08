import React from 'react';
import { useTier } from '../context/TierContext';

/**
 * Application navbar.
 *
 * Authentication has been disabled. Always shows the PRO badge.
 */
export default function Navbar() {
  const { tier, toolUsage, limit, unlimited, loading } = useTier();

  const badgeClass = unlimited ? 'tier-badge paid' : 'tier-badge free';
  const badgeLabel = unlimited ? 'PRO' : `FREE · ${limit}/tool/day`;
  const badgeTitle = unlimited ? 'Unlimited access' : `Free tier: ${limit} uses per tool per day`;

  return (
    <header
      className="app-navbar fixed top-0 left-0 right-0 z-50 flex items-center justify-between"
    >
      <div className="flex items-center gap-3">
        <img src="/assets/logo.png" alt="CyberSec" className="brand-logo w-auto object-contain" />
      </div>

      <div className="flex items-center gap-3 sm:gap-4">
        {!loading && (
          <span className={badgeClass} title={badgeTitle}>
            {badgeLabel}
          </span>
        )}
      </div>
    </header>
  );
}

