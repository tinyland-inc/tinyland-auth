






import { describe, it, expect } from 'vitest';
import { createCSRFHandle } from '../src/adapters/sveltekit/hook.js';
import type { Handle } from '@sveltejs/kit';





interface MockCookies {
  data: Map<string, string>;
  get(name: string): string | undefined;
  set(name: string, value: string): void;
}

interface MockEvent {
  request: Request;
  url: URL;
  cookies: MockCookies;
  locals: Record<string, unknown>;
  getClientAddress?: () => string;
}

function createMockCookies(initial: Record<string, string> = {}): MockCookies {
  const data = new Map(Object.entries(initial));
  return {
    data,
    get(name: string) {
      return data.get(name);
    },
    set(name: string, value: string) {
      data.set(name, value);
    },
  };
}

function createMockEvent(options: {
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
}): MockEvent {
  const { method = 'GET', path = '/', headers = {}, cookies = {} } = options;

  const headerMap = new Headers(headers);

  return {
    request: {
      method,
      headers: headerMap,
    } as unknown as Request,
    url: new URL(`http://localhost${path}`),
    cookies: createMockCookies(cookies),
    locals: {},
  };
}





async function callHandle(
  handle: Handle,
  event: MockEvent
): Promise<Response> {
  const resolve = async (_event: unknown) => new Response('OK', { status: 200 });
  return handle({ event: event as any, resolve: resolve as any });
}





describe('createCSRFHandle', () => {
  describe('safe methods (skip by default)', () => {
    it('should pass through GET requests without token validation', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({ method: 'GET', path: '/api/data' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });

    it('should pass through HEAD requests', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({ method: 'HEAD', path: '/api/data' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });

    it('should pass through OPTIONS requests', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({ method: 'OPTIONS', path: '/api/data' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });
  });

  describe('unsafe methods (POST, PUT, DELETE, PATCH)', () => {
    it('should reject POST with no CSRF token', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({ method: 'POST', path: '/api/submit' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
      expect(await response.text()).toBe('CSRF token invalid');
    });

    it('should reject POST when header token is missing', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({
        method: 'POST',
        path: '/api/submit',
        cookies: { csrf_token: 'valid-token' },
      });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });

    it('should reject POST when cookie token is missing', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({
        method: 'POST',
        path: '/api/submit',
        headers: { 'x-csrf-token': 'valid-token' },
      });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });

    it('should reject POST when tokens do not match', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({
        method: 'POST',
        path: '/api/submit',
        headers: { 'x-csrf-token': 'token-a' },
        cookies: { csrf_token: 'token-b' },
      });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });

    it('should allow POST when header and cookie tokens match', async () => {
      const handle = createCSRFHandle({});
      const token = 'valid-csrf-token-abc123';
      const event = createMockEvent({
        method: 'POST',
        path: '/api/submit',
        headers: { 'x-csrf-token': token },
        cookies: { csrf_token: token },
      });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });

    it('should validate PUT requests', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({ method: 'PUT', path: '/api/update' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });

    it('should validate DELETE requests', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({ method: 'DELETE', path: '/api/remove' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });

    it('should validate PATCH requests', async () => {
      const handle = createCSRFHandle({});
      const event = createMockEvent({ method: 'PATCH', path: '/api/modify' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });
  });

  describe('custom configuration', () => {
    it('should use custom header name', async () => {
      const handle = createCSRFHandle({ tokenHeader: 'x-custom-csrf' });
      const token = 'test-token';
      const event = createMockEvent({
        method: 'POST',
        path: '/api/submit',
        headers: { 'x-custom-csrf': token },
        cookies: { csrf_token: token },
      });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });

    it('should reject when old header name is used with custom config', async () => {
      const handle = createCSRFHandle({ tokenHeader: 'x-custom-csrf' });
      const token = 'test-token';
      const event = createMockEvent({
        method: 'POST',
        path: '/api/submit',
        headers: { 'x-csrf-token': token }, 
        cookies: { csrf_token: token },
      });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });

    it('should use custom cookie name', async () => {
      const handle = createCSRFHandle({ tokenCookie: 'my_csrf' });
      const token = 'test-token';
      const event = createMockEvent({
        method: 'POST',
        path: '/api/submit',
        headers: { 'x-csrf-token': token },
        cookies: { my_csrf: token },
      });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });

    it('should support custom skip methods', async () => {
      const handle = createCSRFHandle({ skipMethods: ['GET', 'POST'] });
      const event = createMockEvent({ method: 'POST', path: '/api/submit' });

      
      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });

    it('should support skip routes', async () => {
      const handle = createCSRFHandle({ skipRoutes: ['/api/webhook'] });
      const event = createMockEvent({ method: 'POST', path: '/api/webhook/stripe' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(200);
    });

    it('should not skip routes that do not match', async () => {
      const handle = createCSRFHandle({ skipRoutes: ['/api/webhook'] });
      const event = createMockEvent({ method: 'POST', path: '/api/submit' });

      const response = await callHandle(handle, event);
      expect(response.status).toBe(403);
    });
  });

  describe('token matching properties', () => {
    it('INVARIANT: same token in header and cookie always passes', async () => {
      const handle = createCSRFHandle({});

      const tokens = [
        'abc123',
        'a'.repeat(64),
        'special-chars_!@#',
        '0',
        'token-with-dashes-and-underscores_123',
      ];

      for (const token of tokens) {
        const event = createMockEvent({
          method: 'POST',
          path: '/api/test',
          headers: { 'x-csrf-token': token },
          cookies: { csrf_token: token },
        });

        const response = await callHandle(handle, event);
        expect(response.status).toBe(200);
      }
    });

    it('INVARIANT: mismatched tokens always fail', async () => {
      const handle = createCSRFHandle({});

      const pairs = [
        ['token-a', 'token-b'],
        ['abc', 'ABC'], 
        ['token-x', 'token-y'], 
        ['', 'non-empty'],
      ];

      for (const [headerToken, cookieToken] of pairs) {
        const event = createMockEvent({
          method: 'POST',
          path: '/api/test',
          headers: { 'x-csrf-token': headerToken },
          cookies: { csrf_token: cookieToken },
        });

        const response = await callHandle(handle, event);
        expect(response.status).toBe(403);
      }
    });
  });
});
