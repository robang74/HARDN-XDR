import { useState, useEffect } from 'react'

interface DeploymentTerminalProps {
  isActive: boolean
  currentStep: number
  onStepChange: (step: number) => void
}

const deploymentSteps = [
  { command: 'hardn-xdr --init', output: 'Initializing HARDN-XDR security framework...', type: 'info' },
  { command: 'hardn-xdr --scan-system', output: 'Scanning system configuration...', type: 'info' },
  { command: 'hardn-xdr --load-modules', output: 'Loading security modules: SSH, UFW, Auditd, File Integrity...', type: 'success' },
  { command: 'hardn-xdr --configure-ssh', output: 'Hardening SSH configuration... [OK]', type: 'success' },
  { command: 'hardn-xdr --setup-firewall', output: 'Configuring firewall rules... [OK]', type: 'success' },
  { command: 'hardn-xdr --enable-audit', output: 'Enabling system auditing... [OK]', type: 'success' },
  { command: 'hardn-xdr --start-monitoring', output: 'Starting real-time monitoring services...', type: 'info' },
  { command: 'hardn-xdr --verify-deployment', output: 'Security deployment completed successfully!', type: 'success' },
]

export default function DeploymentTerminal({ isActive, currentStep, onStepChange }: DeploymentTerminalProps) {
  const [displayedSteps, setDisplayedSteps] = useState<number[]>([])
  const [isTyping, setIsTyping] = useState(false)

  useEffect(() => {
    if (!isActive) {
      setDisplayedSteps([])
      onStepChange(0)
      return
    }

    const timer = setTimeout(() => {
      if (currentStep < deploymentSteps.length) {
        setIsTyping(true)

        // Simulate typing delay
        setTimeout(() => {
          setDisplayedSteps(prev => [...prev, currentStep])
          setIsTyping(false)
          onStepChange(currentStep + 1)
        }, 800 + Math.random() * 400)
      }
    }, 1000)

    return () => clearTimeout(timer)
  }, [isActive, currentStep, onStepChange])

  const getLineClass = (type: string) => {
    switch (type) {
      case 'success': return 'terminal-success'
      case 'warning': return 'terminal-warning'
      case 'error': return 'terminal-error'
      case 'info':
      default: return 'terminal-info'
    }
  }

  return (
    <div className="deployment-terminal">
      <h3>Live Deployment Console</h3>

      <div className="terminal">
        <div className="terminal-header">
          <div className="terminal-dot red"></div>
          <div className="terminal-dot yellow"></div>
          <div className="terminal-dot green"></div>
          <span className="terminal-title">HARDN-XDR Deployment</span>
        </div>

        <div className="terminal-content">
          <div className="terminal-line">
            <span className="terminal-prompt">root@security-platform:~$</span>
            <span className="terminal-command"> hardn-xdr --deploy</span>
          </div>

          {displayedSteps.map((stepIndex) => {
            const step = deploymentSteps[stepIndex]
            return (
              <div key={stepIndex}>
                <div className="terminal-line">
                  <span className="terminal-prompt">→</span>
                  <span className="terminal-command"> {step.command}</span>
                </div>
                <div className={`terminal-line ${getLineClass(step.type)}`}>
                  {step.output}
                </div>
              </div>
            )
          })}

          {isTyping && (
            <div className="terminal-line">
              <span className="terminal-cursor">▋</span>
            </div>
          )}

          {!isActive && displayedSteps.length === 0 && (
            <div className="terminal-line terminal-info">
              Ready to deploy HARDN-XDR security framework...
            </div>
          )}
        </div>
      </div>

      <style jsx>{`
        .deployment-terminal {
          max-width: 800px;
          margin: 0 auto;
        }

        .deployment-terminal h3 {
          text-align: center;
          margin-bottom: var(--spacing-xl);
          color: var(--color-text-accent);
        }

        .terminal-cursor {
          color: var(--color-success);
          animation: blink 1s infinite;
        }

        @keyframes blink {
          0%, 50% { opacity: 1; }
          51%, 100% { opacity: 0; }
        }

        .terminal-info {
          color: var(--color-info);
        }
      `}</style>
    </div>
  )
}
