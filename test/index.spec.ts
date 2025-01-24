// test/index.spec.ts
import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import worker from '../src/index';

const TEST_HTML = `
<!DOCTYPE html>
<html>
<head>
    <script src="https://example.com/script1.js"></script>
    <script>console.log('inline script');</script>
    <style>body { color: blue; }</style>
    <link rel="stylesheet" href="styles.css">
    <style>
        .header { 
            background: red; 
        }
    </style>
</head>
<body>
    <script src="https://example.com/script2.js"></script>
</body>
</html>
`;

describe('CSP Worker Tests', () => {
	let mockEnv: any;
	let mockResponse: Response;
	let request: Request<unknown, IncomingRequestCfProperties>;
	let ctx: ExecutionContext;
	beforeEach(() => {
		// Mock the environment
		mockEnv = {
			ENFORCE_CSP: 'true',
			STYLE_NONCE: 'true'
		};

		// Mock the fetch response
		mockResponse = new Response(TEST_HTML, {
			headers: {
				'content-type': 'text/html'
			}
		});

		
		request = new Request('https://example.com');
		ctx = createExecutionContext();

		// Mock global fetch
		global.fetch = vi.fn().mockResolvedValue(mockResponse);
	});

	it('should inject nonces into all script tags', async () => {
		
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		const html = await response.text();
		
		// All script tags should have a nonce attribute
		expect(html).toMatch(/<script[^>]*nonce="[A-Za-z0-9+/=]+"[^>]*>/g);
		// Should have exactly 3 script tags with nonces
		expect(html.match(/<script[^>]*nonce="[A-Za-z0-9+/=]+"[^>]*>/g)?.length).toBe(3);
	});

	it('should set CSP header when ENFORCE_CSP is true', async () => {
		
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		const cspHeader = response.headers.get('Content-Security-Policy');
		expect(cspHeader).toBeDefined();
		expect(cspHeader).toMatch(/^script-src 'strict-dynamic' 'nonce-[A-Za-z0-9+/=]+' 'unsafe-inline' https:; style-src 'self' 'nonce-[A-Za-z0-9+/=]+'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests$/);
	});

	it('should set CSP-Report-Only header when ENFORCE_CSP is false', async () => {
		mockEnv.ENFORCE_CSP = 'false';
		
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		const cspHeader = response.headers.get('Content-Security-Policy-Report-Only');
		expect(cspHeader).toBeDefined();
		expect(cspHeader).toMatch(/^script-src 'strict-dynamic' 'nonce-[A-Za-z0-9+/=]+' 'unsafe-inline' https:; style-src 'self' 'nonce-[A-Za-z0-9+/=]+'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests$/);
	});

	it('should not modify non-HTML responses', async () => {
		// Mock a JSON response
		const jsonResponse = new Response('{"test": true}', {
			headers: {
				'content-type': 'application/json'
			}
		});
		global.fetch = vi.fn().mockResolvedValue(jsonResponse);
		
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		// Should not have CSP headers
		expect(response.headers.get('Content-Security-Policy')).toBeNull();
		expect(response.headers.get('Content-Security-Policy-Report-Only')).toBeNull();
		
		// Content should be unchanged
		const json = await response.json();
		expect(json).toEqual({ test: true });
	});

	it('should generate valid base64 nonces', async () => {
		
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		const html = await response.text();
		const nonceMatch = html.match(/nonce="([A-Za-z0-9+/=]+)"/);
		expect(nonceMatch).toBeTruthy();
		
		// Nonce should be valid base64 and 24 characters (16 bytes in base64)
		const nonce = nonceMatch![1];
		expect(nonce).toMatch(/^[A-Za-z0-9+/=]{24}$/);
	});

	it('should inject nonces into all style tags', async () => {
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		const html = await response.text();
		
		// All style tags should have a nonce attribute
		expect(html).toMatch(/<style[^>]*nonce="[A-Za-z0-9+/=]+"[^>]*>/g);
		// Should have exactly 2 style tags with nonces
		expect(html.match(/<style[^>]*nonce="[A-Za-z0-9+/=]+"[^>]*>/g)?.length).toBe(2);
	});

	it('should include style-src in CSP header with correct nonce', async () => {
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		const cspHeader = response.headers.get('Content-Security-Policy');
		expect(cspHeader).toBeDefined();
		expect(cspHeader).toContain("style-src 'self' 'nonce-");
		
		// Extract nonce from style tag
		const html = await response.text();
		const nonceMatch = html.match(/style[^>]*nonce="([A-Za-z0-9+/=]+)"/);
		expect(nonceMatch).toBeTruthy();
		
		// Verify the same nonce is used in the CSP header
		const nonce = nonceMatch![1];
		expect(cspHeader).toContain(`'nonce-${nonce}'`);
	});

	it('should not inject nonces into style tags when STYLE_NONCE is false', async () => {
		mockEnv.STYLE_NONCE = 'false';
		
		const response = await worker.fetch(request, mockEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		const html = await response.text();
		
		// Style tags should not have nonce attributes
		expect(html).not.toMatch(/<style[^>]*nonce="[A-Za-z0-9+/=]+"[^>]*>/g);
		// Script tags should still have nonce attributes
		expect(html).toMatch(/<script[^>]*nonce="[A-Za-z0-9+/=]+"[^>]*>/g);
		
		// CSP header should use unsafe-inline for styles
		const cspHeader = response.headers.get('Content-Security-Policy');
		expect(cspHeader).toContain("style-src 'self' 'unsafe-inline'");
	});
});
