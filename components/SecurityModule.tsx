import { useState, useEffect } from 'react'

interface SecurityModuleProps {
  name: string
  status: 'active' | 'monitoring' | 'scanning' | 'inactive'
  coverage: number
  delay?: number
}

export default function SecurityModule({ name, status, coverage, delay = 0 }: SecurityModuleProps) {
  const [isVisible, setIsVisible] = useState(false)
  const [animatedCoverage, setAnimatedCoverage] = useState(0)

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(true)
    }, delay)

    return () => clearTimeout(timer)
  }, [delay])

  useEffect(() => {
    if (isVisible) {
      const timer = setTimeout(() => {
        animateCoverage()
      }, 300)
      return () => clearTimeout(timer)
    }
  }, [isVisible, coverage])

  const animateCoverage = () => {
    let current = 0
    const increment = coverage / 30
    const timer = setInterval(() => {
      current += increment
      if (current >= coverage) {
        setAnimatedCoverage(coverage)
        clearInterval(timer)
      } else {
        setAnimatedCoverage(Math.floor(current))
      }
    }, 50)
  }

  const getStatusColor = () => {
    switch (status) {
      case 'active': return 'var(--color-success)'
      case 'monitoring': return 'var(--color-info)'
      case 'scanning': return 'var(--color-warning)'
      case 'inactive': return 'var(--color-error)'
      default: return 'var(--color-secondary)'
    }
  }

  const getCoverageColor = () => {
    if (animatedCoverage >= 95) return 'var(--color-success)'
    if (animatedCoverage >= 80) return 'var(--color-warning)'
    return 'var(--color-error)'
  }

  return (
    <div className={`security-module ${isVisible ? 'visible' : ''}`}>
      <div className="module-header">
        <h4>{name}</h4>
        <div className={`status-indicator status-${status}`}>
          <div className="status-dot" style={{ background: getStatusColor() }}></div>
          {status.charAt(0).toUpperCase() + status.slice(1)}
        </div>
      </div>

      <div className="module-content">
        <div className="coverage-section">
          <div className="coverage-label">Coverage</div>
          <div className="coverage-value" style={{ color: getCoverageColor() }}>
            {animatedCoverage}%
          </div>
        </div>

        <div className="coverage-bar">
          <div 
            className="coverage-fill"
            style={{ 
              width: `${animatedCoverage}%`,
              background: getCoverageColor()
            }}
          ></div>
        </div>

        <div className="module-details">
          <div className="detail-item">
            <span className="detail-label">Last Scan:</span>
            <span className="detail-value">2 minutes ago</span>
          </div>
          <div className="detail-item">
            <span className="detail-label">Threats:</span>
            <span className="detail-value">0 detected</span>
          </div>
        </div>
      </div>

      <style jsx>{`
        .security-module {
          background: var(--color-bg-card);
          border: 1px solid var(--color-border-primary);
          border-radius: var(--radius-lg);
          padding: var(--spacing-lg);
          transition: all var(--transition-normal);
          opacity: 0;
          transform: translateY(20px);
        }

        .security-module.visible {
          opacity: 1;
          transform: translateY(0);
        }

        .security-module:hover {
          border-color: var(--color-border-accent);
          box-shadow: var(--shadow-md);
          transform: translateY(-2px);
        }

        .module-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: var(--spacing-md);
        }

        .module-header h4 {
          margin: 0;
          color: var(--color-text-accent);
          font-size: 1.125rem;
        }

        .coverage-section {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: var(--spacing-sm);
        }

        .coverage-label {
          color: var(--color-text-secondary);
          font-size: 0.875rem;
        }

        .coverage-value {
          font-size: 1.5rem;
          font-weight: 600;
          font-family: var(--font-family-mono);
        }

        .coverage-bar {
          width: 100%;
          height: 8px;
          background: var(--color-bg-secondary);
          border-radius: var(--radius-sm);
          margin-bottom: var(--spacing-md);
          overflow: hidden;
        }

        .coverage-fill {
          height: 100%;
          border-radius: var(--radius-sm);
          transition: width 1s ease-out;
          position: relative;
        }

        .coverage-fill::after {
          content: '';
          position: absolute;
          top: 0;
          right: 0;
          bottom: 0;
          width: 20px;
          background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3));
          animation: shimmer 2s infinite;
        }

        @keyframes shimmer {
          0% { transform: translateX(-20px); }
          100% { transform: translateX(20px); }
        }

        .module-details {
          display: flex;
          flex-direction: column;
          gap: var(--spacing-xs);
        }

        .detail-item {
          display: flex;
          justify-content: space-between;
          font-size: 0.875rem;
        }

        .detail-label {
          color: var(--color-text-tertiary);
        }

        .detail-value {
          color: var(--color-text-secondary);
          font-family: var(--font-family-mono);
        }
      `}</style>
    </div>
  )
}
