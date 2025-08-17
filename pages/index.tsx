import { useState, useEffect } from 'react'
import Head from 'next/head'
import Layout from '../components/Layout'
import DeploymentTerminal from '../components/DeploymentTerminal'
import SecurityModule from '../components/SecurityModule'
import SystemStatus from '../components/SystemStatus'

export default function Home() {
  const [isDeploying, setIsDeploying] = useState(false)
  const [deploymentStep, setDeploymentStep] = useState(0)

  const securityModules = [
    { name: 'SSH Hardening', status: 'active', coverage: 98 },
    { name: 'Firewall Rules', status: 'active', coverage: 100 },
    { name: 'Audit System', status: 'active', coverage: 95 },
    { name: 'File Integrity', status: 'monitoring', coverage: 92 },
    { name: 'Network Monitor', status: 'active', coverage: 89 },
    { name: 'Malware Scanner', status: 'scanning', coverage: 94 }
  ]

  const startDeployment = () => {
    setIsDeploying(true)
    setDeploymentStep(0)
  }

  return (
    <>
      <Head>
        <title>HARDN-XDR - Security Platform Deployment</title>
        <meta name="description" content="Advanced XDR security framework deployment platform" />
      </Head>

      <Layout>
        <div className="deployment-platform">
          {/* Hero Section */}
          <section className="hero-section">
            <div className="hero-content">
              <h1 className="hero-title">HARDN-XDR</h1>
              <p className="hero-subtitle">Extended Detection & Response Security Framework</p>
              <div className="hero-description">
                Comprehensive hardening and monitoring solution for Linux systems.
                Deploy enterprise-grade security with automated threat detection and response.
              </div>

              <div className="hero-actions">
                <button 
                  className="btn btn-primary" 
                  onClick={startDeployment}
                  disabled={isDeploying}
                >
                  {isDeploying ? 'Deploying...' : 'Start Deployment'}
                </button>
                <a href="/docs" className="btn btn-secondary">
                  View Documentation
                </a>
              </div>
            </div>

            <div className="hero-visual">
              <SystemStatus />
            </div>
          </section>

          {/* Deployment Terminal */}
          <section className="terminal-section">
            <DeploymentTerminal 
              isActive={isDeploying}
              currentStep={deploymentStep}
              onStepChange={setDeploymentStep}
            />
          </section>

          {/* Security Modules Grid */}
          <section className="modules-section">
            <h2 className="section-title">Security Modules Status</h2>
            <div className="modules-grid">
              {securityModules.map((module, index) => (
                <SecurityModule
                  key={module.name}
                  name={module.name}
                  status={module.status}
                  coverage={module.coverage}
                  delay={index * 100}
                />
              ))}
            </div>
          </section>

          {/* Platform Features */}
          <section className="features-section">
            <h2 className="section-title">Platform Capabilities</h2>
            <div className="features-grid">
              <div className="feature-card">
                <div className="feature-icon">🛡️</div>
                <h3>System Hardening</h3>
                <p>Automated security configuration based on industry standards including CIS and DISA STIG compliance.</p>
              </div>

              <div className="feature-card">
                <div className="feature-icon">👁️</div>
                <h3>Extended Detection</h3>
                <p>Advanced threat detection using behavioral analysis, ML algorithms, and real-time monitoring.</p>
              </div>

              <div className="feature-card">
                <div className="feature-icon">⚡</div>
                <h3>Automated Response</h3>
                <p>Immediate threat containment and automated incident response with configurable playbooks.</p>
              </div>

              <div className="feature-card">
                <div className="feature-icon">📊</div>
                <h3>Compliance Reporting</h3>
                <p>Real-time compliance dashboards and automated audit reporting for regulatory requirements.</p>
              </div>
            </div>
          </section>
        </div>
      </Layout>
    </>
  )
}
