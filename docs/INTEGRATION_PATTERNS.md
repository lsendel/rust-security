# Integration Patterns & Best Practices

## Table of Contents

1. [Architecture Patterns](#architecture-patterns)
2. [Security Patterns](#security-patterns)
3. [Performance Patterns](#performance-patterns)
4. [Monitoring & Observability](#monitoring--observability)
5. [Error Handling Patterns](#error-handling-patterns)
6. [Testing Strategies](#testing-strategies)
7. [Production Deployment](#production-deployment)

---

# Architecture Patterns

## Microservices Integration Pattern

### Gateway-Based Integration

```typescript
// api-gateway/src/security-proxy.ts
import { RustSecuritySDK } from '@rust-security/sdk';
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';

class SecurityAwareGateway {
  private sdk: RustSecuritySDK;
  private serviceRegistry: Map<string, ServiceConfig>;

  constructor(config: GatewayConfig) {
    this.sdk = new RustSecuritySDK(config.rustSecurity);
    this.serviceRegistry = new Map(config.services.map(s => [s.name, s]));
  }

  createSecureProxy(serviceName: string) {
    const serviceConfig = this.serviceRegistry.get(serviceName);
    if (!serviceConfig) {
      throw new Error(`Service ${serviceName} not registered`);
    }

    return createProxyMiddleware({
      target: serviceConfig.url,
      changeOrigin: true,
      pathRewrite: serviceConfig.pathRewrite,
      
      // Security-aware request transformation
      onProxyReq: async (proxyReq, req, res) => {
        // Add service-to-service authentication
        const serviceToken = await this.getServiceToken(serviceName);
        proxyReq.setHeader('Authorization', `Bearer ${serviceToken}`);
        
        // Add request metadata for audit
        proxyReq.setHeader('X-Request-ID', req.headers['x-request-id']);
        proxyReq.setHeader('X-User-ID', req.user?.userId);
        proxyReq.setHeader('X-Session-ID', req.user?.sessionId);
        
        // Policy enforcement
        await this.enforceServicePolicy(req, serviceName);
      },
      
      // Response transformation and audit
      onProxyRes: (proxyRes, req, res) => {
        // Audit successful service calls
        this.auditServiceCall({
          service: serviceName,
          method: req.method,
          path: req.path,
          userId: req.user?.userId,
          statusCode: proxyRes.statusCode,
          responseTime: Date.now() - req.startTime
        });
        
        // Add security headers
        proxyRes.headers['X-Content-Type-Options'] = 'nosniff';
        proxyRes.headers['X-Frame-Options'] = 'DENY';
      }
    });
  }

  private async getServiceToken(serviceName: string): Promise<string> {
    // Use client credentials flow for service-to-service authentication
    const cached = this.tokenCache.get(serviceName);
    if (cached && !this.isTokenExpired(cached.token)) {
      return cached.token;
    }

    const tokenResponse = await this.sdk.auth.getServiceToken({
      clientId: `service-${serviceName}`,
      clientSecret: process.env[`${serviceName.toUpperCase()}_SECRET`],
      scope: [`${serviceName}:access`]
    });

    this.tokenCache.set(serviceName, {
      token: tokenResponse.accessToken,
      expiresAt: Date.now() + (tokenResponse.expiresIn * 1000)
    });

    return tokenResponse.accessToken;
  }

  private async enforceServicePolicy(req: express.Request, serviceName: string) {
    if (!req.user) return; // Skip for public endpoints

    const policyResult = await this.sdk.policy.authorize({
      requestId: req.headers['x-request-id'] as string,
      principal: { type: 'User', id: req.user.userId },
      action: { type: 'Action', id: `${serviceName}::${req.method}` },
      resource: { type: 'Service', id: `${serviceName}:${req.path}` },
      context: {
        serviceGateway: true,
        targetService: serviceName,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }
    });

    if (policyResult.decision !== 'Allow') {
      throw new PolicyViolationError(
        `Service access denied: ${policyResult.reasons.join(', ')}`,
        policyResult.requestId
      );
    }
  }
}

// Usage
const gateway = new SecurityAwareGateway({
  rustSecurity: {
    baseUrl: process.env.RUST_SECURITY_API_URL,
    apiKey: process.env.RUST_SECURITY_API_KEY
  },
  services: [
    {
      name: 'user-service',
      url: 'http://user-service:3001',
      pathRewrite: { '^/api/users': '' }
    },
    {
      name: 'order-service', 
      url: 'http://order-service:3002',
      pathRewrite: { '^/api/orders': '' }
    }
  ]
});

app.use('/api/users', gateway.createSecureProxy('user-service'));
app.use('/api/orders', gateway.createSecureProxy('order-service'));
```

### Event-Driven Security Integration

```typescript
// events/security-event-handler.ts
import { EventEmitter } from 'events';
import { RustSecuritySDK } from '@rust-security/sdk';

interface SecurityEvent {
  type: string;
  timestamp: Date;
  source: string;
  data: any;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

class SecurityEventOrchestrator extends EventEmitter {
  private sdk: RustSecuritySDK;
  private eventBuffer: SecurityEvent[] = [];
  private processingInterval: NodeJS.Timeout;

  constructor(sdk: RustSecuritySDK) {
    super();
    this.sdk = sdk;
    this.setupEventHandlers();
    this.startEventProcessing();
  }

  private setupEventHandlers() {
    // Authentication events
    this.on('auth.login_failed', this.handleFailedLogin.bind(this));
    this.on('auth.suspicious_location', this.handleSuspiciousLocation.bind(this));
    this.on('auth.mfa_bypass_attempt', this.handleMfaBypass.bind(this));

    // Application events
    this.on('app.anomalous_api_usage', this.handleApiAnomaly.bind(this));
    this.on('app.sensitive_data_access', this.handleSensitiveAccess.bind(this));
    this.on('app.privilege_escalation', this.handlePrivilegeEscalation.bind(this));

    // Infrastructure events
    this.on('infra.suspicious_network_traffic', this.handleNetworkAnomaly.bind(this));
    this.on('infra.system_compromise_indicator', this.handleSystemCompromise.bind(this));
  }

  emitSecurityEvent(event: SecurityEvent) {
    this.eventBuffer.push(event);
    this.emit(event.type, event);
  }

  private async handleFailedLogin(event: SecurityEvent) {
    const { userId, ipAddress, failureCount } = event.data;

    // Check if this indicates a potential brute force attack
    if (failureCount >= 5) {
      const incident = await this.sdk.soar.incidents.create({
        title: `Potential Brute Force Attack on ${userId}`,
        description: `${failureCount} failed login attempts from ${ipAddress}`,
        severity: 'medium',
        category: 'brute_force_attack',
        affectedAssets: [
          {
            type: 'user_account',
            identifier: userId,
            criticality: 'medium'
          }
        ],
        evidence: [
          {
            type: 'authentication_log',
            timestamp: event.timestamp.toISOString(),
            source: event.source,
            data: event.data
          }
        ]
      });

      // Trigger automated response
      await this.sdk.soar.playbooks.execute('pb_brute_force_response', {
        incidentId: incident.incidentId,
        parameters: {
          targetUser: userId,
          sourceIp: ipAddress,
          blockDuration: '1 hour'
        }
      });
    }
  }

  private async handleSuspiciousLocation(event: SecurityEvent) {
    const { userId, newLocation, previousLocation, impossibleTravel } = event.data;

    if (impossibleTravel) {
      const incident = await this.sdk.soar.incidents.create({
        title: `Impossible Travel Detected for ${userId}`,
        description: `User logged in from ${newLocation.country} while previous login was from ${previousLocation.country}`,
        severity: 'high',
        category: 'account_compromise',
        affectedAssets: [
          {
            type: 'user_account',
            identifier: userId,
            criticality: 'high'
          }
        ],
        evidence: [
          {
            type: 'geolocation_analysis',
            timestamp: event.timestamp.toISOString(),
            source: 'behavioral_analysis',
            data: {
              previous_location: previousLocation,
              current_location: newLocation,
              travel_time_required: event.data.travelTimeRequired,
              actual_time_elapsed: event.data.actualTimeElapsed
            }
          }
        ]
      });

      // Immediate account lock and investigation
      await this.sdk.soar.playbooks.execute('pb_account_compromise_response', {
        incidentId: incident.incidentId,
        parameters: {
          userId,
          immediateAction: 'lock_account',
          notifyUser: true,
          requireStepUpAuth: true
        }
      });
    }
  }

  private startEventProcessing() {
    this.processingInterval = setInterval(async () => {
      if (this.eventBuffer.length > 0) {
        const events = this.eventBuffer.splice(0, 100); // Process in batches
        await this.performCorrelationAnalysis(events);
      }
    }, 30000); // Process every 30 seconds
  }

  private async performCorrelationAnalysis(events: SecurityEvent[]) {
    // Group events by user, IP, and time window
    const correlatedEvents = this.correlateEvents(events);
    
    for (const correlation of correlatedEvents) {
      if (correlation.riskScore > 0.8) {
        await this.createCorrelatedIncident(correlation);
      }
    }
  }

  private correlateEvents(events: SecurityEvent[]) {
    const correlations = [];
    const timeWindow = 10 * 60 * 1000; // 10 minutes
    
    // Group events by potential indicators
    const groupedEvents = new Map();
    
    events.forEach(event => {
      const keys = this.getCorrelationKeys(event);
      keys.forEach(key => {
        if (!groupedEvents.has(key)) {
          groupedEvents.set(key, []);
        }
        groupedEvents.get(key).push(event);
      });
    });

    // Analyze grouped events for suspicious patterns
    groupedEvents.forEach((eventGroup, key) => {
      if (eventGroup.length >= 3) { // Minimum events for correlation
        const correlation = this.analyzeEventGroup(eventGroup, key);
        if (correlation.riskScore > 0.5) {
          correlations.push(correlation);
        }
      }
    });

    return correlations;
  }

  private getCorrelationKeys(event: SecurityEvent): string[] {
    const keys = [];
    
    if (event.data.userId) {
      keys.push(`user:${event.data.userId}`);
    }
    if (event.data.ipAddress) {
      keys.push(`ip:${event.data.ipAddress}`);
    }
    if (event.data.sessionId) {
      keys.push(`session:${event.data.sessionId}`);
    }
    
    return keys;
  }

  private analyzeEventGroup(events: SecurityEvent[], key: string) {
    const uniqueEventTypes = new Set(events.map(e => e.type)).size;
    const timeSpan = Math.max(...events.map(e => e.timestamp.getTime())) - 
                    Math.min(...events.map(e => e.timestamp.getTime()));
    
    const severityScore = events.reduce((sum, e) => {
      const scores = { low: 1, medium: 2, high: 3, critical: 4 };
      return sum + scores[e.severity];
    }, 0) / events.length;

    // Calculate risk score based on various factors
    let riskScore = 0;
    
    // Multiple event types indicate sophisticated attack
    if (uniqueEventTypes >= 3) riskScore += 0.3;
    
    // Events in short timespan indicate coordinated attack
    if (timeSpan < 5 * 60 * 1000) riskScore += 0.2; // 5 minutes
    
    // High severity events
    if (severityScore >= 3) riskScore += 0.3;
    
    // Volume of events
    if (events.length >= 5) riskScore += 0.2;

    return {
      key,
      events,
      riskScore: Math.min(riskScore, 1.0),
      eventCount: events.length,
      uniqueEventTypes,
      timeSpan,
      avgSeverity: severityScore
    };
  }
}
```

---

# Security Patterns

## Zero Trust Integration Pattern

```typescript
// security/zero-trust-enforcer.ts
import { RustSecuritySDK } from '@rust-security/sdk';

class ZeroTrustEnforcer {
  private sdk: RustSecuritySDK;
  private deviceTrust: DeviceTrustManager;
  private locationTrust: LocationTrustManager;
  private behaviorTrust: BehaviorTrustManager;

  constructor(sdk: RustSecuritySDK) {
    this.sdk = sdk;
    this.deviceTrust = new DeviceTrustManager(sdk);
    this.locationTrust = new LocationTrustManager(sdk);
    this.behaviorTrust = new BehaviorTrustManager(sdk);
  }

  async enforceZeroTrust(request: AuthRequest): Promise<TrustDecision> {
    const trustFactors = await Promise.all([
      this.evaluateIdentityTrust(request),
      this.deviceTrust.evaluate(request),
      this.locationTrust.evaluate(request),
      this.behaviorTrust.evaluate(request),
      this.evaluateResourceSensitivity(request),
      this.evaluateNetworkTrust(request)
    ]);

    const overallTrustScore = this.calculateTrustScore(trustFactors);
    const requiredTrustLevel = this.getRequiredTrustLevel(request);

    return {
      trustScore: overallTrustScore,
      requiredTrustLevel,
      decision: overallTrustScore >= requiredTrustLevel ? 'Allow' : 'Deny',
      factors: trustFactors,
      requirements: this.getAdditionalRequirements(overallTrustScore, requiredTrustLevel),
      riskMitigation: this.getRiskMitigationActions(trustFactors)
    };
  }

  private async evaluateIdentityTrust(request: AuthRequest): Promise<TrustFactor> {
    const user = await this.sdk.auth.getUser(request.userId);
    
    let score = 0.5; // Base score
    
    // Strong authentication
    if (user.mfaEnabled) score += 0.2;
    if (request.mfaVerified) score += 0.1;
    if (request.authMethod === 'webauthn') score += 0.1;
    
    // Account standing
    if (user.accountAge > 90) score += 0.1; // days
    if (user.suspiciousActivityCount === 0) score += 0.1;
    
    // Privilege level (inverse trust - higher privileges = more scrutiny)
    if (user.roles.includes('admin')) score -= 0.1;
    if (user.roles.includes('privileged')) score -= 0.05;

    return {
      type: 'identity',
      score: Math.max(0, Math.min(1, score)),
      confidence: 0.9,
      details: {
        mfaEnabled: user.mfaEnabled,
        mfaVerified: request.mfaVerified,
        authMethod: request.authMethod,
        accountAge: user.accountAge,
        privilegeLevel: this.getPrivilegeLevel(user.roles)
      }
    };
  }

  private async evaluateResourceSensitivity(request: AuthRequest): Promise<TrustFactor> {
    const resource = await this.getResourceMetadata(request.resourceId);
    
    let requiredTrust = 0.5; // Base requirement
    
    // Data classification
    if (resource.classification === 'public') requiredTrust = 0.3;
    if (resource.classification === 'internal') requiredTrust = 0.5;
    if (resource.classification === 'confidential') requiredTrust = 0.7;
    if (resource.classification === 'secret') requiredTrust = 0.9;
    
    // Compliance requirements
    if (resource.complianceFlags?.includes('PCI')) requiredTrust += 0.1;
    if (resource.complianceFlags?.includes('HIPAA')) requiredTrust += 0.1;
    if (resource.complianceFlags?.includes('SOX')) requiredTrust += 0.1;

    return {
      type: 'resource_sensitivity',
      score: 1.0 - requiredTrust, // Invert for trust score
      confidence: 0.95,
      details: {
        classification: resource.classification,
        complianceFlags: resource.complianceFlags,
        requiredTrustLevel: requiredTrust
      }
    };
  }

  private calculateTrustScore(factors: TrustFactor[]): number {
    const weights = {
      identity: 0.25,
      device: 0.20,
      location: 0.15,
      behavior: 0.20,
      resource_sensitivity: 0.10,
      network: 0.10
    };

    let weightedSum = 0;
    let totalWeight = 0;

    factors.forEach(factor => {
      const weight = weights[factor.type] || 0.1;
      weightedSum += factor.score * factor.confidence * weight;
      totalWeight += weight;
    });

    return weightedSum / totalWeight;
  }

  private getAdditionalRequirements(
    trustScore: number,
    requiredLevel: number
  ): AdditionalRequirement[] {
    const requirements: AdditionalRequirement[] = [];
    const gap = requiredLevel - trustScore;

    if (gap > 0.3) {
      requirements.push({
        type: 'step_up_authentication',
        description: 'Additional authentication required',
        methods: ['webauthn', 'sms_otp', 'push_notification']
      });
    }

    if (gap > 0.2) {
      requirements.push({
        type: 'device_verification',
        description: 'Device must be verified and registered',
        action: 'register_device'
      });
    }

    if (gap > 0.1) {
      requirements.push({
        type: 'session_monitoring',
        description: 'Enhanced session monitoring required',
        duration: '1 hour'
      });
    }

    return requirements;
  }

  private getRiskMitigationActions(factors: TrustFactor[]): RiskMitigation[] {
    const mitigations: RiskMitigation[] = [];

    factors.forEach(factor => {
      if (factor.score < 0.5) {
        switch (factor.type) {
          case 'location':
            mitigations.push({
              type: 'geo_restriction',
              action: 'limit_access_to_known_locations',
              duration: '24 hours'
            });
            break;
          case 'device':
            mitigations.push({
              type: 'device_restriction',
              action: 'require_device_registration',
              validation: 'admin_approval'
            });
            break;
          case 'behavior':
            mitigations.push({
              type: 'behavioral_monitoring',
              action: 'enhanced_activity_logging',
              alerting: 'real_time'
            });
            break;
        }
      }
    });

    return mitigations;
  }
}

class DeviceTrustManager {
  constructor(private sdk: RustSecuritySDK) {}

  async evaluate(request: AuthRequest): Promise<TrustFactor> {
    const deviceInfo = request.deviceInfo;
    let score = 0.3; // Base score for any device
    
    // Device registration status
    const registeredDevice = await this.sdk.auth.getRegisteredDevice(
      request.userId,
      deviceInfo.fingerprint
    );
    
    if (registeredDevice) {
      score += 0.3;
      
      // Device trust history
      if (registeredDevice.trustLevel === 'high') score += 0.2;
      if (registeredDevice.trustLevel === 'medium') score += 0.1;
      
      // Recent compromise indicators
      if (registeredDevice.lastSecurityScan) {
        const daysSinceLastScan = this.daysSince(registeredDevice.lastSecurityScan);
        if (daysSinceLastScan < 7) score += 0.1;
        if (daysSinceLastScan > 30) score -= 0.1;
      }
    } else {
      // Unknown device - reduce trust
      score -= 0.2;
    }

    // Device security posture
    if (deviceInfo.jailbroken || deviceInfo.rooted) score -= 0.3;
    if (deviceInfo.osVersion && this.isOSVersionCurrent(deviceInfo.osVersion)) {
      score += 0.1;
    }

    // Corporate vs personal device
    if (deviceInfo.managedDevice) score += 0.2;
    if (deviceInfo.certificateInstalled) score += 0.1;

    return {
      type: 'device',
      score: Math.max(0, Math.min(1, score)),
      confidence: registeredDevice ? 0.9 : 0.6,
      details: {
        registered: !!registeredDevice,
        trustLevel: registeredDevice?.trustLevel,
        managed: deviceInfo.managedDevice,
        securityPosture: this.assessSecurityPosture(deviceInfo)
      }
    };
  }

  private assessSecurityPosture(deviceInfo: any) {
    const indicators = [];
    
    if (deviceInfo.jailbroken || deviceInfo.rooted) {
      indicators.push('compromised_os');
    }
    if (!this.isOSVersionCurrent(deviceInfo.osVersion)) {
      indicators.push('outdated_os');
    }
    if (!deviceInfo.screenLockEnabled) {
      indicators.push('no_screen_lock');
    }
    
    return {
      riskIndicators: indicators,
      overallPosture: indicators.length === 0 ? 'good' : 
                     indicators.length <= 2 ? 'moderate' : 'poor'
    };
  }
}
```

## Adaptive Authentication Pattern

```typescript
// auth/adaptive-auth.ts
interface AdaptiveAuthRequest {
  userId: string;
  requestedAction: string;
  context: AuthContext;
  currentAuthLevel: number;
}

interface AuthContext {
  deviceTrust: number;
  locationTrust: number;
  behaviorTrust: number;
  networkTrust: number;
  timeTrust: number;
  requestSensitivity: number;
}

class AdaptiveAuthenticationEngine {
  private sdk: RustSecuritySDK;
  private riskEngine: RiskAssessmentEngine;
  private authMethods: Map<string, AuthMethod>;

  constructor(sdk: RustSecuritySDK) {
    this.sdk = sdk;
    this.riskEngine = new RiskAssessmentEngine(sdk);
    this.initializeAuthMethods();
  }

  async evaluateAuthRequirement(request: AdaptiveAuthRequest): Promise<AuthDecision> {
    // Calculate composite risk score
    const riskAssessment = await this.riskEngine.assess(request);
    
    // Determine required authentication level
    const requiredAuthLevel = this.calculateRequiredAuthLevel(
      request.requestedAction,
      request.context,
      riskAssessment
    );

    // Check if current auth is sufficient
    if (request.currentAuthLevel >= requiredAuthLevel) {
      return {
        decision: 'allow',
        currentLevel: request.currentAuthLevel,
        requiredLevel: requiredAuthLevel,
        riskScore: riskAssessment.score
      };
    }

    // Determine step-up authentication requirements
    const stepUpMethods = this.selectStepUpMethods(
      request.currentAuthLevel,
      requiredAuthLevel,
      riskAssessment
    );

    return {
      decision: 'step_up_required',
      currentLevel: request.currentAuthLevel,
      requiredLevel: requiredAuthLevel,
      riskScore: riskAssessment.score,
      stepUpMethods,
      fallbackOptions: this.getFallbackOptions(request, riskAssessment)
    };
  }

  private calculateRequiredAuthLevel(
    action: string,
    context: AuthContext,
    risk: RiskAssessment
  ): number {
    // Base authentication level based on action sensitivity
    let baseLevel = this.getActionSensitivityLevel(action);
    
    // Adjust based on context factors
    const contextRisk = 1 - Math.min(
      context.deviceTrust,
      context.locationTrust,
      context.behaviorTrust,
      context.networkTrust,
      context.timeTrust
    );

    // Risk-based adjustment
    const riskMultiplier = 1 + (risk.score * 0.5);
    
    return Math.min(4, Math.ceil(baseLevel * riskMultiplier + contextRisk));
  }

  private selectStepUpMethods(
    currentLevel: number,
    requiredLevel: number,
    risk: RiskAssessment
  ): StepUpMethod[] {
    const levelGap = requiredLevel - currentLevel;
    const methods: StepUpMethod[] = [];

    if (levelGap >= 1) {
      // Level 1: Something you know
      methods.push({
        type: 'password_confirmation',
        strength: 1,
        userFriendly: true,
        estimatedTime: 30
      });
    }

    if (levelGap >= 2) {
      // Level 2: Something you have
      methods.push({
        type: 'totp',
        strength: 2,
        userFriendly: true,
        estimatedTime: 45,
        fallback: ['sms_otp', 'backup_codes']
      });
    }

    if (levelGap >= 3) {
      // Level 3: Something you are
      methods.push({
        type: 'webauthn',
        strength: 3,
        userFriendly: true,
        estimatedTime: 60,
        fallback: ['push_notification']
      });
    }

    if (levelGap >= 4 || risk.score > 0.8) {
      // Level 4: High assurance
      methods.push({
        type: 'admin_approval',
        strength: 4,
        userFriendly: false,
        estimatedTime: 300,
        description: 'Administrative approval required for high-risk access'
      });
    }

    return methods;
  }

  private getFallbackOptions(
    request: AdaptiveAuthRequest,
    risk: RiskAssessment
  ): FallbackOption[] {
    const options: FallbackOption[] = [];

    // Time-based fallback
    if (risk.score < 0.7) {
      options.push({
        type: 'time_delay',
        description: 'Wait 15 minutes and retry with lower requirements',
        waitTime: 900,
        reducedRequirement: true
      });
    }

    // Approval-based fallback
    if (request.context.requestSensitivity < 0.8) {
      options.push({
        type: 'supervisor_approval',
        description: 'Request supervisor approval for access',
        approvers: this.getUserSupervisors(request.userId),
        timeout: 3600
      });
    }

    // Restricted access fallback
    options.push({
      type: 'restricted_access',
      description: 'Grant limited access with enhanced monitoring',
      restrictions: [
        'read_only_access',
        'time_limited_session',
        'enhanced_logging'
      ],
      sessionDuration: 1800
    });

    return options;
  }

  async executeStepUpAuthentication(
    userId: string,
    method: StepUpMethod,
    challengeData: any
  ): Promise<StepUpResult> {
    const authMethod = this.authMethods.get(method.type);
    if (!authMethod) {
      throw new Error(`Unsupported authentication method: ${method.type}`);
    }

    try {
      const result = await authMethod.verify(userId, challengeData);
      
      if (result.success) {
        // Update user's authentication level
        await this.updateUserAuthLevel(userId, method.strength);
        
        // Log successful step-up
        await this.auditStepUpAuth(userId, method.type, 'success');
        
        return {
          success: true,
          newAuthLevel: method.strength,
          validityPeriod: this.getValidityPeriod(method.strength),
          sessionExtended: true
        };
      } else {
        await this.auditStepUpAuth(userId, method.type, 'failure', result.reason);
        
        return {
          success: false,
          reason: result.reason,
          attemptsRemaining: result.attemptsRemaining,
          lockoutTime: result.lockoutTime
        };
      }
    } catch (error) {
      await this.auditStepUpAuth(userId, method.type, 'error', error.message);
      throw error;
    }
  }

  private initializeAuthMethods() {
    this.authMethods = new Map([
      ['password_confirmation', new PasswordConfirmationAuth(this.sdk)],
      ['totp', new TotpAuth(this.sdk)],
      ['sms_otp', new SmsOtpAuth(this.sdk)],
      ['push_notification', new PushNotificationAuth(this.sdk)],
      ['webauthn', new WebAuthnAuth(this.sdk)],
      ['admin_approval', new AdminApprovalAuth(this.sdk)]
    ]);
  }

  private getActionSensitivityLevel(action: string): number {
    const sensitivityMap: Record<string, number> = {
      // Read operations
      'read_profile': 1,
      'read_public_data': 1,
      
      // Standard operations
      'update_profile': 2,
      'create_resource': 2,
      
      // Sensitive operations
      'delete_resource': 3,
      'access_sensitive_data': 3,
      'financial_transaction': 3,
      
      // Administrative operations
      'admin_access': 4,
      'system_configuration': 4,
      'user_management': 4
    };

    return sensitivityMap[action] || 2; // Default to level 2
  }

  private getValidityPeriod(authLevel: number): number {
    // Higher auth levels have shorter validity periods
    const validityMap: Record<number, number> = {
      1: 24 * 60 * 60, // 24 hours
      2: 8 * 60 * 60,  // 8 hours
      3: 2 * 60 * 60,  // 2 hours
      4: 30 * 60       // 30 minutes
    };

    return validityMap[authLevel] || 60 * 60; // Default 1 hour
  }
}
```

---

# Performance Patterns

## Caching Strategy Pattern

```typescript
// cache/security-cache.ts
import { Redis } from 'ioredis';
import { RustSecuritySDK } from '@rust-security/sdk';

interface CacheOptions {
  ttl: number;
  tags: string[];
  version?: string;
}

class SecurityAwareCache {
  private redis: Redis;
  private sdk: RustSecuritySDK;
  private encryptionKey: Buffer;

  constructor(redisUrl: string, sdk: RustSecuritySDK) {
    this.redis = new Redis(redisUrl);
    this.sdk = sdk;
    this.encryptionKey = this.generateEncryptionKey();
  }

  async get<T>(
    key: string,
    options?: {
      decrypt?: boolean;
      validatePolicy?: boolean;
      userId?: string;
    }
  ): Promise<T | null> {
    try {
      let data = await this.redis.get(key);
      if (!data) return null;

      // Decrypt if required
      if (options?.decrypt) {
        data = this.decrypt(data);
      }

      const cachedItem: CachedItem<T> = JSON.parse(data);

      // Check expiration
      if (Date.now() > cachedItem.expiresAt) {
        await this.redis.del(key);
        return null;
      }

      // Policy validation for sensitive data
      if (options?.validatePolicy && options?.userId) {
        const canAccess = await this.validateCacheAccess(
          options.userId,
          key,
          cachedItem.securityTags
        );
        if (!canAccess) {
          return null;
        }
      }

      return cachedItem.data;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set<T>(
    key: string,
    data: T,
    options: CacheOptions & {
      encrypt?: boolean;
      securityTags?: string[];
    }
  ): Promise<void> {
    try {
      const cachedItem: CachedItem<T> = {
        data,
        createdAt: Date.now(),
        expiresAt: Date.now() + (options.ttl * 1000),
        version: options.version || '1.0',
        securityTags: options.securityTags || [],
        tags: options.tags
      };

      let serialized = JSON.stringify(cachedItem);

      // Encrypt sensitive data
      if (options.encrypt) {
        serialized = this.encrypt(serialized);
      }

      await this.redis.setex(key, options.ttl, serialized);

      // Add to tag indexes for invalidation
      await this.addToTagIndexes(key, options.tags);

    } catch (error) {
      console.error('Cache set error:', error);
      throw error;
    }
  }

  async invalidateByTags(tags: string[]): Promise<number> {
    let invalidatedCount = 0;

    for (const tag of tags) {
      const tagKey = `tag:${tag}`;
      const keys = await this.redis.smembers(tagKey);
      
      if (keys.length > 0) {
        await this.redis.del(...keys);
        await this.redis.del(tagKey);
        invalidatedCount += keys.length;
      }
    }

    return invalidatedCount;
  }

  private async validateCacheAccess(
    userId: string,
    cacheKey: string,
    securityTags: string[]
  ): Promise<boolean> {
    // For highly sensitive cached data, validate access permissions
    if (securityTags.includes('pii') || securityTags.includes('financial')) {
      try {
        const result = await this.sdk.policy.authorize({
          requestId: `cache_access_${Date.now()}`,
          principal: { type: 'User', id: userId },
          action: { type: 'Action', id: 'Cache::Read' },
          resource: { type: 'CachedData', id: cacheKey },
          context: {
            cacheKey,
            securityTags,
            accessTime: new Date().toISOString()
          }
        });

        return result.decision === 'Allow';
      } catch (error) {
        console.error('Policy validation for cache access failed:', error);
        return false;
      }
    }

    return true;
  }

  private encrypt(data: string): string {
    // Implementation would use proper encryption
    // This is a simplified example
    const cipher = crypto.createCipher('aes-256-cbc', this.encryptionKey);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private decrypt(encryptedData: string): string {
    const decipher = crypto.createDecipher('aes-256-cbc', this.encryptionKey);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  private async addToTagIndexes(key: string, tags: string[]): Promise<void> {
    const pipeline = this.redis.pipeline();
    
    for (const tag of tags) {
      pipeline.sadd(`tag:${tag}`, key);
      pipeline.expire(`tag:${tag}`, 86400); // 24 hours
    }
    
    await pipeline.exec();
  }
}

// Usage example with smart caching patterns
class SmartCachingService {
  private cache: SecurityAwareCache;
  private sdk: RustSecuritySDK;

  constructor(cache: SecurityAwareCache, sdk: RustSecuritySDK) {
    this.cache = cache;
    this.sdk = sdk;
  }

  // Cache user permissions with policy validation
  async getCachedUserPermissions(userId: string): Promise<string[]> {
    const cacheKey = `user:${userId}:permissions`;
    
    let permissions = await this.cache.get<string[]>(cacheKey, {
      validatePolicy: true,
      userId
    });

    if (!permissions) {
      // Fetch from API
      const user = await this.sdk.auth.getUser(userId);
      permissions = user.permissions;

      // Cache with appropriate TTL and security tags
      await this.cache.set(cacheKey, permissions, {
        ttl: 3600, // 1 hour
        tags: [`user:${userId}`, 'permissions'],
        securityTags: ['user_data'],
        encrypt: false // Permissions are not PII
      });
    }

    return permissions;
  }

  // Cache policy evaluation results
  async getCachedPolicyEvaluation(
    userId: string,
    action: string,
    resource: string
  ): Promise<PolicyResult | null> {
    const cacheKey = `policy:${userId}:${action}:${resource}`;
    
    return await this.cache.get<PolicyResult>(cacheKey, {
      validatePolicy: true,
      userId
    });
  }

  async cachePolicyEvaluation(
    userId: string,
    action: string,
    resource: string,
    result: PolicyResult
  ): Promise<void> {
    const cacheKey = `policy:${userId}:${action}:${resource}`;
    
    // Shorter TTL for policy decisions to ensure freshness
    await this.cache.set(cacheKey, result, {
      ttl: 300, // 5 minutes
      tags: [`user:${userId}`, 'policy_decisions', `resource:${resource}`],
      securityTags: ['policy_data'],
      version: '1.0'
    });
  }

  // Cache sensitive data with encryption
  async getCachedSensitiveData(
    userId: string,
    dataType: string
  ): Promise<SensitiveData | null> {
    const cacheKey = `sensitive:${userId}:${dataType}`;
    
    return await this.cache.get<SensitiveData>(cacheKey, {
      decrypt: true,
      validatePolicy: true,
      userId
    });
  }

  async cacheSensitiveData(
    userId: string,
    dataType: string,
    data: SensitiveData
  ): Promise<void> {
    const cacheKey = `sensitive:${userId}:${dataType}`;
    
    await this.cache.set(cacheKey, data, {
      ttl: 1800, // 30 minutes
      tags: [`user:${userId}`, `datatype:${dataType}`],
      securityTags: ['pii', 'sensitive'],
      encrypt: true, // Always encrypt sensitive data
      version: '2.0'
    });
  }

  // Invalidate cache on security events
  async handleSecurityEvent(event: SecurityEvent): Promise<void> {
    switch (event.type) {
      case 'user.permissions_changed':
        await this.cache.invalidateByTags([`user:${event.userId}`, 'permissions']);
        break;
        
      case 'policy.updated':
        await this.cache.invalidateByTags(['policy_decisions']);
        break;
        
      case 'user.security_incident':
        // Invalidate all user-related cached data
        await this.cache.invalidateByTags([`user:${event.userId}`]);
        break;
        
      case 'resource.access_revoked':
        await this.cache.invalidateByTags([`resource:${event.resourceId}`]);
        break;
    }
  }
}
```

## Connection Pooling Pattern

```typescript
// connection/pool-manager.ts
class ConnectionPoolManager {
  private pools: Map<string, ConnectionPool>;
  private sdk: RustSecuritySDK;
  private healthChecker: HealthChecker;

  constructor(sdk: RustSecuritySDK) {
    this.sdk = sdk;
    this.pools = new Map();
    this.healthChecker = new HealthChecker();
    this.initializePools();
  }

  private initializePools() {
    // Auth service pool
    this.pools.set('auth', new ConnectionPool({
      name: 'auth-service',
      baseUrl: process.env.RUST_SECURITY_AUTH_URL,
      minConnections: 5,
      maxConnections: 20,
      idleTimeout: 60000,
      healthCheckInterval: 30000
    }));

    // Policy service pool
    this.pools.set('policy', new ConnectionPool({
      name: 'policy-service',
      baseUrl: process.env.RUST_SECURITY_POLICY_URL,
      minConnections: 10,
      maxConnections: 50, // Policy evaluation is high-frequency
      idleTimeout: 30000,
      healthCheckInterval: 15000
    }));

    // SOAR service pool
    this.pools.set('soar', new ConnectionPool({
      name: 'soar-service',
      baseUrl: process.env.RUST_SECURITY_SOAR_URL,
      minConnections: 2,
      maxConnections: 10,
      idleTimeout: 120000, // Longer timeout for investigation workflows
      healthCheckInterval: 60000
    }));
  }

  async executeWithPool<T>(
    serviceName: string,
    operation: (connection: Connection) => Promise<T>
  ): Promise<T> {
    const pool = this.pools.get(serviceName);
    if (!pool) {
      throw new Error(`No pool configured for service: ${serviceName}`);
    }

    const connection = await pool.acquire();
    
    try {
      return await operation(connection);
    } finally {
      pool.release(connection);
    }
  }

  async getPoolStats(): Promise<Record<string, PoolStats>> {
    const stats: Record<string, PoolStats> = {};
    
    for (const [name, pool] of this.pools) {
      stats[name] = await pool.getStats();
    }
    
    return stats;
  }

  async healthCheck(): Promise<Record<string, HealthStatus>> {
    const health: Record<string, HealthStatus> = {};
    
    for (const [name, pool] of this.pools) {
      health[name] = await this.healthChecker.check(pool);
    }
    
    return health;
  }
}

class ConnectionPool {
  private config: PoolConfig;
  private available: Connection[];
  private busy: Set<Connection>;
  private waitingQueue: Array<{
    resolve: (conn: Connection) => void;
    reject: (error: Error) => void;
  }>;
  private healthCheckTimer: NodeJS.Timeout;

  constructor(config: PoolConfig) {
    this.config = config;
    this.available = [];
    this.busy = new Set();
    this.waitingQueue = [];
    
    this.initialize();
    this.startHealthChecks();
  }

  private async initialize() {
    // Create minimum connections
    for (let i = 0; i < this.config.minConnections; i++) {
      const connection = await this.createConnection();
      this.available.push(connection);
    }
  }

  private async createConnection(): Promise<Connection> {
    return new Connection({
      baseUrl: this.config.baseUrl,
      timeout: 30000,
      retries: 3
    });
  }

  async acquire(): Promise<Connection> {
    return new Promise((resolve, reject) => {
      // Check for available connection
      if (this.available.length > 0) {
        const connection = this.available.pop()!;
        this.busy.add(connection);
        resolve(connection);
        return;
      }

      // Create new connection if under limit
      if (this.busy.size < this.config.maxConnections) {
        this.createConnection().then(connection => {
          this.busy.add(connection);
          resolve(connection);
        }).catch(reject);
        return;
      }

      // Add to waiting queue
      this.waitingQueue.push({ resolve, reject });
      
      // Set timeout for waiting requests
      setTimeout(() => {
        const index = this.waitingQueue.findIndex(
          item => item.resolve === resolve
        );
        if (index > -1) {
          this.waitingQueue.splice(index, 1);
          reject(new Error('Connection pool timeout'));
        }
      }, 10000);
    });
  }

  release(connection: Connection): void {
    this.busy.delete(connection);
    
    // Serve waiting requests first
    if (this.waitingQueue.length > 0) {
      const waiter = this.waitingQueue.shift()!;
      this.busy.add(connection);
      waiter.resolve(connection);
      return;
    }

    // Check connection health before returning to pool
    if (connection.isHealthy()) {
      this.available.push(connection);
    } else {
      // Replace unhealthy connection
      this.createConnection().then(newConnection => {
        this.available.push(newConnection);
      }).catch(error => {
        console.error('Failed to replace unhealthy connection:', error);
      });
    }

    // Remove excess connections
    if (this.available.length > this.config.minConnections) {
      const excess = this.available.splice(this.config.minConnections);
      excess.forEach(conn => conn.close());
    }
  }

  private startHealthChecks(): void {
    this.healthCheckTimer = setInterval(async () => {
      await this.performHealthCheck();
    }, this.config.healthCheckInterval);
  }

  private async performHealthCheck(): void {
    const healthyConnections: Connection[] = [];
    
    // Check available connections
    for (const connection of this.available) {
      if (await connection.performHealthCheck()) {
        healthyConnections.push(connection);
      } else {
        connection.close();
      }
    }
    
    this.available = healthyConnections;
    
    // Replenish if below minimum
    while (this.available.length < this.config.minConnections) {
      try {
        const newConnection = await this.createConnection();
        this.available.push(newConnection);
      } catch (error) {
        console.error('Failed to create replacement connection:', error);
        break;
      }
    }
  }

  async getStats(): Promise<PoolStats> {
    return {
      name: this.config.name,
      available: this.available.length,
      busy: this.busy.size,
      waiting: this.waitingQueue.length,
      total: this.available.length + this.busy.size,
      maxConnections: this.config.maxConnections,
      minConnections: this.config.minConnections
    };
  }

  async destroy(): Promise<void> {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    const allConnections = [...this.available, ...this.busy];
    await Promise.all(allConnections.map(conn => conn.close()));
    
    this.available = [];
    this.busy.clear();
    
    // Reject all waiting requests
    this.waitingQueue.forEach(waiter => {
      waiter.reject(new Error('Connection pool destroyed'));
    });
    this.waitingQueue = [];
  }
}
```

This comprehensive integration patterns guide provides production-ready examples for:

1. **Architecture patterns** including microservices gateway integration and event-driven security
2. **Zero Trust security patterns** with comprehensive trust evaluation
3. **Adaptive authentication** with risk-based step-up requirements
4. **Performance optimization** through intelligent caching and connection pooling
5. **Real-world integration examples** with proper error handling and monitoring

Each pattern demonstrates best practices for enterprise-scale applications that need robust security, high performance, and maintainable code architecture.