













export interface CSRFState {
  token: string | null;
  tokenHash: string | null;
  issuedAt: number | null;
  expiresAt: number | null;
  role: string | null;
}




export interface CSRFStoreConfig {
  
  headerName: string;
  
  cookieName: string;
  
  tokenLifetimeMs: number;
  
  refreshThresholdMs: number;
  
  tokenEndpoint: string;
}

const DEFAULT_CONFIG: CSRFStoreConfig = {
  headerName: 'x-csrf-token',
  cookieName: 'csrf_token',
  tokenLifetimeMs: 24 * 60 * 60 * 1000, 
  refreshThresholdMs: 30 * 60 * 1000, 
  tokenEndpoint: '/api/csrf-token',
};





function hashToken(token: string): string {
  let hash = 0;
  for (let i = 0; i < token.length; i++) {
    const char = token.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}




function readTokenFromCookie(cookieName: string): string | null {
  if (typeof document === 'undefined') return null;

  const cookies = document.cookie.split(';').map((c: string) => c.trim());
  const csrfCookie = cookies.find((c: string) => c.startsWith(`${cookieName}=`));

  if (csrfCookie) {
    const token = csrfCookie.split('=')[1];
    return decodeURIComponent(token);
  }

  return null;
}






















export function createCSRFStore(config: Partial<CSRFStoreConfig> = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  
  let state = $state<CSRFState>({
    token: null,
    tokenHash: null,
    issuedAt: null,
    expiresAt: null,
    role: null,
  });

  
  const isValid = $derived(
    state.token !== null &&
    state.expiresAt !== null &&
    Date.now() < state.expiresAt
  );

  const isExpiringSoon = $derived(
    state.expiresAt !== null &&
    Date.now() > state.expiresAt - cfg.refreshThresholdMs
  );

  const timeUntilExpiry = $derived(
    state.expiresAt !== null
      ? Math.max(0, state.expiresAt - Date.now())
      : null
  );

  


  function initialize(token: string, role?: string) {
    const now = Date.now();
    state = {
      token,
      tokenHash: hashToken(token),
      issuedAt: now,
      expiresAt: now + cfg.tokenLifetimeMs,
      role: role ?? null,
    };
  }

  


  async function fetchToken(): Promise<string | null> {
    try {
      
      const cookieToken = readTokenFromCookie(cfg.cookieName);
      if (cookieToken) {
        initialize(cookieToken);
        return cookieToken;
      }

      
      const response = await fetch(cfg.tokenEndpoint, {
        method: 'GET',
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json() as { token?: string };
        if (data.token) {
          initialize(data.token);
          return data.token;
        }
      }
    } catch (error) {
      console.error('[CSRF Store] Failed to fetch token:', error);
    }

    return null;
  }

  


  async function rotateOnRoleChange(newRole: string): Promise<void> {
    if (state.role === newRole) {
      return;
    }

    console.log(`[CSRF Store] Rotating token due to role change: ${state.role} → ${newRole}`);

    try {
      const response = await fetch(cfg.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          reason: 'role_change',
          previousRole: state.role,
          newRole,
        }),
      });

      if (response.ok) {
        const data = await response.json() as { token?: string };
        if (data.token) {
          initialize(data.token, newRole);
          console.log('[CSRF Store] Token rotated successfully');
        }
      } else {
        console.error('[CSRF Store] Failed to rotate token:', response.status);
      }
    } catch (error) {
      console.error('[CSRF Store] Token rotation error:', error);
    }
  }

  


  async function refreshIfNeeded(): Promise<void> {
    if (!isExpiringSoon) return;

    console.log('[CSRF Store] Token expiring soon, refreshing');

    try {
      const response = await fetch(cfg.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ reason: 'refresh' }),
      });

      if (response.ok) {
        const data = await response.json() as { token?: string };
        if (data.token) {
          initialize(data.token, state.role ?? undefined);
          console.log('[CSRF Store] Token refreshed successfully');
        }
      }
    } catch (error) {
      console.error('[CSRF Store] Token refresh error:', error);
    }
  }

  


  function getHeaders(): Record<string, string> {
    if (!state.token || !isValid) {
      console.warn('[CSRF Store] No valid token available for request');
      return {};
    }
    return { [cfg.headerName]: state.token };
  }

  


  function validate(token: string): boolean {
    if (!state.token) return false;
    return token === state.token && isValid;
  }

  


  function clear() {
    console.log('[CSRF Store] Clearing token');
    state = {
      token: null,
      tokenHash: null,
      issuedAt: null,
      expiresAt: null,
      role: null,
    };
  }

  


  function setRole(role: string | null) {
    state.role = role;
  }

  return {
    
    get token() { return state.token; },
    get isValid() { return isValid; },
    get isExpiringSoon() { return isExpiringSoon; },
    get role() { return state.role; },
    get timeUntilExpiry() { return timeUntilExpiry; },
    get expiresAt() { return state.expiresAt; },

    
    initialize,
    fetchToken,
    rotateOnRoleChange,
    refreshIfNeeded,
    getHeaders,
    validate,
    clear,
    setRole,

    
    config: cfg,
  };
}




export const csrfStore = createCSRFStore();


export const getCSRFHeaders = () => csrfStore.getHeaders();
export const validateCSRF = (token: string) => csrfStore.validate(token);
export const refreshCSRF = () => csrfStore.refreshIfNeeded();
