








import type { AdminUser, AdminRole, AdminInvitation, AuthErrorCode } from './auth.js';








export interface BootstrapRequest {
  
  handle: string;
  
  password: string;
  
  displayName: string;
  
  email?: string;
}




export interface BootstrapResponse {
  success: boolean;
  
  user?: Omit<AdminUser, 'passwordHash'>;
  
  totpSecret?: string;
  
  qrCodeUrl?: string;
  
  backupCodes?: string[];
  error?: string;
}




export interface BootstrapVerificationRequest {
  
  handle: string;
  
  totpCode: string;
}




export interface BootstrapStatus {
  
  needsBootstrap: boolean;
  
  hasUsers: boolean;
  
  systemConfigured: boolean;
}








export interface LoginRequest {
  
  handle: string;
  
  password: string;
  
  totpCode?: string;
  
  rememberMe?: boolean;
}




export interface LoginResponse {
  success: boolean;
  
  user?: Omit<AdminUser, 'passwordHash'>;
  
  sessionToken?: string;
  
  needsOnboarding?: boolean;
  
  error?: AuthErrorCode;
  
  errorMessage?: string;
  
  metadata?: {
    
    totpRequired: boolean;
    
    accountLocked: boolean;
    
    attemptsRemaining?: number;
  };
}




export interface LogoutRequest {
  
  sessionId?: string;
  
  logoutAll?: boolean;
}




export interface LogoutResponse {
  success: boolean;
  
  sessionsTerminated?: number;
  error?: string;
}








export interface SessionInfo {
  id: string;
  userId: string;
  handle: string;
  role: AdminRole;
  displayName?: string;
  createdAt: string;
  expiresAt: string;
  lastActivity?: string;
  ipAddress?: string;
  userAgent?: string;
  isValid: boolean;
  isCurrent: boolean;
  deviceInfo?: {
    platform?: string;
    browser?: string;
    isMobile?: boolean;
  };
}




export interface SessionRefreshRequest {
  sessionId: string;
}




export interface SessionRefreshResponse {
  success: boolean;
  
  sessionToken?: string;
  
  expiresAt?: string;
  error?: string;
}




export interface SessionListResponse {
  success: boolean;
  sessions: SessionInfo[];
  currentSessionId: string;
  error?: string;
}




export interface SessionTerminateRequest {
  
  sessionId: string;
}




export interface SessionTerminateResponse {
  success: boolean;
  error?: string;
}








export interface InvitationCreateRequest {
  
  email: string;
  
  role: AdminRole;
  
  expiresInHours?: number;
  
  message?: string;
  
  customInstructions?: string;
  
  skipEmailNotification?: boolean;
}




export interface InvitationCreateResponse {
  success: boolean;
  invitation?: AdminInvitation;
  
  inviteUrl?: string;
  
  totpSecret?: string;
  
  qrCodeUrl?: string;
  error?: string;
}




export interface InvitationAcceptRequest {
  
  token: string;
  
  handle: string;
  
  password: string;
  
  totpCode: string;
  
  displayName?: string;
  
  email?: string;
}




export interface InvitationAcceptResponse {
  success: boolean;
  user?: Omit<AdminUser, 'passwordHash'>;
  
  permanentTotpSecret?: string;
  
  backupCodes?: string[];
  
  needsOnboarding: boolean;
  error?: string;
}




export interface InvitationListResponse {
  success: boolean;
  invitations: AdminInvitation[];
  statistics: {
    total: number;
    pending: number;
    expired: number;
    used: number;
  };
  error?: string;
}




export interface InvitationRevokeRequest {
  
  tokenOrId: string;
}




export interface InvitationRevokeResponse {
  success: boolean;
  error?: string;
}








export interface OnboardingStatus {
  
  needsOnboarding: boolean;
  
  currentStep: number;
  
  completedSteps: number[];
  
  canSkip: boolean;
  
  estimatedTimeRemaining: string;
}




export interface ProfileSetupRequest {
  displayName: string;
  bio?: string;
  pronouns?: string;
  avatarUrl?: string;
}




export interface SecurityReviewRequest {
  
  confirmTotpEnabled: boolean;
  
  downloadedBackupCodes: boolean;
  
  acknowledgeSecurityGuidelines: boolean;
  
  additionalSecurityMeasures?: {
    enableLoginNotifications?: boolean;
    enableLocationTracking?: boolean;
  };
}




export interface PreferencesSetupRequest {
  timezone: string;
  locale: string;
  theme: 'light' | 'dark' | 'auto';
  emailNotifications: boolean;
  additionalPreferences?: {
    digestFrequency?: 'daily' | 'weekly' | 'monthly' | 'never';
    securityAlerts?: boolean;
    featureUpdates?: boolean;
  };
}




export interface OnboardingStepResponse {
  success: boolean;
  
  nextStep?: number | null;
  
  isComplete?: boolean;
  error?: string;
}




export interface OnboardingSkipRequest {
  
  acknowledgeSkip: boolean;
}








export interface TOTPSetupRequest {
  
  secret: string;
  
  verificationCode: string;
}




export interface TOTPSetupResponse {
  success: boolean;
  
  backupCodes?: string[];
  
  qrCodeUrl?: string;
  error?: string;
}




export interface TOTPDisableRequest {
  
  password: string;
  
  verificationCode: string;
}




export interface TOTPDisableResponse {
  success: boolean;
  error?: string;
}




export interface BackupCodeUsageRequest {
  
  backupCode: string;
  
  purpose: 'login' | 'disable_totp' | 'account_recovery';
}




export interface BackupCodeUsageResponse {
  success: boolean;
  
  codesRemaining: number;
  
  regenerationRequired?: boolean;
  error?: string;
}




export interface BackupCodesRegenerateRequest {
  
  password: string;
  
  totpCode: string;
}




export interface BackupCodesRegenerateResponse {
  success: boolean;
  
  backupCodes?: string[];
  error?: string;
}








export interface PasswordChangeRequest {
  
  currentPassword: string;
  
  newPassword: string;
  
  confirmPassword: string;
  
  totpCode?: string;
}




export interface PasswordChangeResponse {
  success: boolean;
  
  sessionsTerminated?: boolean;
  error?: string;
}








export interface UserListRequest {
  
  role?: AdminRole;
  
  isActive?: boolean;
  
  search?: string;
  
  page?: number;
  
  limit?: number;
}




export interface UserListResponse {
  success: boolean;
  users: Array<Omit<AdminUser, 'passwordHash'>>;
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
  error?: string;
}




export interface UserUpdateRequest {
  userId: string;
  updates: {
    role?: AdminRole;
    isActive?: boolean;
    isLocked?: boolean;
    lockReason?: string;
    permissions?: string[];
  };
}




export interface UserUpdateResponse {
  success: boolean;
  user?: Omit<AdminUser, 'passwordHash'>;
  error?: string;
}




export interface UserDeleteRequest {
  userId: string;
  
  confirmDelete: boolean;
}




export interface UserDeleteResponse {
  success: boolean;
  error?: string;
}
