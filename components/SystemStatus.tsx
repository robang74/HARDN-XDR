import { useState, useEffect } from 'react'

export default function SystemStatus() {
  const [metrics, setMetrics] = useState({
    cpu: 0,
    memory: 0,
    network: 0,
    threats: 0
  })

  useEffect(() => {
    const interval = setInterval(() => {
      setMetrics({
        cpu: 15 + Math.random() * 10,
        memory: 45 + Math.random() * 15,
        network: 20 + Math.random() * 30,
        threats: 0
      })
    }, 2000)

    // Initial animation
    setTimeout(() => {
      setMetrics({
        cpu: 18.5,
        memory: 52.3,
        network: 34.7,
        threats: 0
      })
    }, 500)

    return () => clearInterval(interval)
  }, [])

  const MetricCard = ({ label, value, unit, color, icon }: {
    label: string
    value: number
    unit: string
    color: string
    icon: string
  }) => (
    <div className="metric-card">
      <div className="metric-icon">{icon}</div>
      <div className="metric-content">
        <div className="metric-label">{label}</div>
        <div className="metric-value" style={{ color }}>
          {value.toFixed(1)}{unit}
        </div>
      </div>
      <div className="metric-bar">
        <div 
          className="metric-fill"
          style={{ 
            width: `${Math.min(value, 100)}%`,
            background: color
          }}
        ></div>
      </div>
    </div>
  )

  return (
    <div className="system-status">
      <div className="status-header">
        <h3>System Status</h3>
        <div className="status-indicator">
          <div className="status-dot secure"></div>
          Secure
        </div>
      </div>

      <div className="metrics-grid">
        <MetricCard
          label="CPU Usage"
          value={metrics.cpu}
          unit="%"
          color="var(--color-info)"
          icon="⚡"
        />
        <MetricCard
          label="Memory"
          value={metrics.memory}
          unit="%"
          color="var(--color-warning)"
          icon="💾"
        />
        <MetricCard
          label="Network"
          value={metrics.network}
          unit="MB/s"
          color="var(--color-success)"
          icon="🌐"
        />
        <MetricCard
          label="Threats"
          value={metrics.threats}
          unit=""
          color="var(--color-success)"
          icon="🛡️"
        />
      </div>

      <div className="security-overview">
        <div className="overview-item">
          <span className="overview-label">Security Level:</span>
          <span className="overview-value high">High</span>
        </div>
        <div className="overview-item">
          <span className="overview-label">Last Scan:</span>
          <span className="overview-value">Just now</span>
        </div>
        <div className="overview-item">
          <span className="overview-label">Active Modules:</span>
          <span className="overview-value">12/12</span>
        </div>
      </div>

      <style jsx>{`
        .system-status {
          background: var(--color-bg-card);
          border: 1px solid var(--color-border-primary);
          border-radius: var(--radius-xl);
          padding: var(--spacing-xl);
          box-shadow: var(--shadow-lg);
          max-width: 400px;
        }

        .status-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: var(--spacing-lg);
        }

        .status-header h3 {
          margin: 0;
          color: var(--color-text-accent);
        }

        .status-indicator {
          display: flex;
          align-items: center;
          gap: var(--spacing-xs);
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--color-success);
        }

        .status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          animation: pulse 2s infinite;
        }

        .status-dot.secure {
          background: var(--color-success);
        }

        .metrics-grid {
          display: flex;
          flex-direction: column;
          gap: var(--spacing-md);
          margin-bottom: var(--spacing-xl);
        }

        .metric-card {
          display: flex;
          align-items: center;
          gap: var(--spacing-md);
          padding: var(--spacing-md);
          background: var(--color-bg-secondary);
          border-radius: var(--radius-md);
          border: 1px solid var(--color-border-primary);
        }

        .metric-icon {
          font-size: 1.5rem;
          width: 32px;
          text-align: center;
        }

        .metric-content {
          flex: 1;
          min-width: 0;
        }

        .metric-label {
          font-size: 0.75rem;
          color: var(--color-text-tertiary);
          margin-bottom: var(--spacing-xs);
        }

        .metric-value {
          font-size: 1.25rem;
          font-weight: 600;
          font-family: var(--font-family-mono);
        }

        .metric-bar {
          width: 60px;
          height: 4px;
          background: var(--color-bg-primary);
          border-radius: var(--radius-sm);
          overflow: hidden;
        }

        .metric-fill {
          height: 100%;
          border-radius: var(--radius-sm);
          transition: width 0.5s ease-out;
        }

        .security-overview {
          display: flex;
          flex-direction: column;
          gap: var(--spacing-sm);
        }

        .overview-item {
          display: flex;
          justify-content: space-between;
          font-size: 0.875rem;
        }

        .overview-label {
          color: var(--color-text-secondary);
        }

        .overview-value {
          font-family: var(--font-family-mono);
          color: var(--color-text-primary);
        }

        .overview-value.high {
          color: var(--color-success);
          font-weight: 600;
        }

        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}
