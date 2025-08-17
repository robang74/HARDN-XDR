import { ReactNode } from 'react'

interface LayoutProps {
  children: ReactNode
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="layout">
      <nav className="navbar">
        <div className="navbar-content">
          <div className="navbar-brand">
            <h3>HARDN-XDR</h3>
            <span className="navbar-tagline">Security Platform</span>
          </div>

          <div className="navbar-links">
            <a href="#features" className="navbar-link">Features</a>
            <a href="#modules" className="navbar-link">Modules</a>
            <a href="/docs" className="navbar-link">Docs</a>
            <a 
              href="https://github.com/OpenSource-For-Freedom/HARDN-XDR" 
              className="navbar-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub
            </a>
          </div>
        </div>
      </nav>

      <main className="main-content">
        {children}
      </main>

      <footer className="footer">
        <div className="footer-content">
          <div className="footer-section">
            <h4>HARDN-XDR</h4>
            <p>Open-source security hardening and XDR framework for Linux systems.</p>
          </div>

          <div className="footer-section">
            <h5>Resources</h5>
            <a href="/docs">Documentation</a>
            <a href="/docs/installation">Installation</a>
            <a href="/docs/stig-compliance">STIG Compliance</a>
          </div>

          <div className="footer-section">
            <h5>Community</h5>
            <a href="https://github.com/OpenSource-For-Freedom/HARDN-XDR">GitHub</a>
            <a href="https://github.com/OpenSource-For-Freedom/HARDN-XDR/issues">Issues</a>
            <a href="https://github.com/OpenSource-For-Freedom/HARDN-XDR/discussions">Discussions</a>
          </div>

          <div className="footer-section">
            <h5>Legal</h5>
            <a href="/docs/code-of-conduct">Code of Conduct</a>
            <a href="https://github.com/OpenSource-For-Freedom/HARDN-XDR/blob/main/LICENSE">License</a>
          </div>
        </div>

        <div className="footer-bottom">
          <p>&copy; 2024 OpenSource-For-Freedom. Released under MIT License.</p>
        </div>
      </footer>

      <style jsx>{`
        .navbar {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          background: rgba(10, 10, 10, 0.95);
          backdrop-filter: blur(10px);
          border-bottom: 1px solid var(--color-border-primary);
          z-index: 1000;
          padding: 0 var(--spacing-xl);
        }

        .navbar-content {
          display: flex;
          align-items: center;
          justify-content: space-between;
          max-width: 1200px;
          margin: 0 auto;
          height: 64px;
        }

        .navbar-brand h3 {
          margin: 0;
          color: var(--color-text-accent);
          font-size: 1.5rem;
          font-weight: 700;
        }

        .navbar-tagline {
          color: var(--color-text-tertiary);
          font-size: 0.875rem;
          margin-left: var(--spacing-sm);
        }

        .navbar-links {
          display: flex;
          gap: var(--spacing-lg);
          align-items: center;
        }

        .navbar-link {
          color: var(--color-text-secondary);
          text-decoration: none;
          font-weight: 500;
          transition: color var(--transition-fast);
        }

        .navbar-link:hover {
          color: var(--color-text-accent);
        }

        .main-content {
          margin-top: 64px;
          min-height: calc(100vh - 64px);
        }

        .footer {
          background: var(--color-bg-secondary);
          border-top: 1px solid var(--color-border-primary);
          padding: var(--spacing-3xl) var(--spacing-xl) var(--spacing-xl);
        }

        .footer-content {
          max-width: 1200px;
          margin: 0 auto;
          display: grid;
          grid-template-columns: 2fr 1fr 1fr 1fr;
          gap: var(--spacing-2xl);
        }

        .footer-section h4,
        .footer-section h5 {
          color: var(--color-text-accent);
          margin-bottom: var(--spacing-md);
          font-size: 1rem;
        }

        .footer-section p {
          color: var(--color-text-secondary);
          line-height: 1.6;
          margin: 0;
        }

        .footer-section a {
          display: block;
          color: var(--color-text-secondary);
          text-decoration: none;
          margin-bottom: var(--spacing-sm);
          transition: color var(--transition-fast);
        }

        .footer-section a:hover {
          color: var(--color-text-accent);
        }

        .footer-bottom {
          max-width: 1200px;
          margin: 0 auto;
          text-align: center;
          padding-top: var(--spacing-xl);
          border-top: 1px solid var(--color-border-primary);
          margin-top: var(--spacing-xl);
        }

        .footer-bottom p {
          color: var(--color-text-tertiary);
          font-size: 0.875rem;
          margin: 0;
        }

        @media (max-width: 768px) {
          .navbar {
            padding: 0 var(--spacing-md);
          }

          .navbar-links {
            gap: var(--spacing-md);
          }

          .navbar-tagline {
            display: none;
          }

          .footer-content {
            grid-template-columns: 1fr;
            gap: var(--spacing-xl);
          }
        }
      `}</style>
    </div>
  )
}
