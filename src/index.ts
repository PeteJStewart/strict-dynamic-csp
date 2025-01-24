// Define the Env interface for environment variables
interface Env {
    ENFORCE_CSP: string;
    STYLE_NONCE: string;
}

// Function to generate a secure nonce using the Web Crypto API
async function generateNonce(): Promise<string> {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array));
}

// Handler class for injecting nonce into script tags using HTMLRewriter
class ScriptNonceHandler {
    private nonce: string;

    constructor(nonce: string) {
        this.nonce = nonce;
    }

    element(element: Element) {
        element.setAttribute('nonce', this.nonce);
    }
}

// Main request handler
async function handleRequest(request: Request, env: Env): Promise<Response> {
    const response = await fetch(request);
    const contentType = response.headers.get('content-type');

    if (contentType && contentType.includes('text/html')) {
        const nonce = await generateNonce();
        const rewriter = new HTMLRewriter()
            .on('script', new ScriptNonceHandler(nonce));
        
        // Conditionally add style nonce handler
        if (env.STYLE_NONCE === 'true') {
            rewriter.on('style', new ScriptNonceHandler(nonce));
        }

        const modifiedResponse = rewriter.transform(response);

        // Determine CSP mode based on environment variable
        const cspMode = env.ENFORCE_CSP === 'true' ? '' : '-Report-Only';
        
        // Build CSP directives array
        const cspDirectives = [
            `script-src 'strict-dynamic' 'nonce-${nonce}' 'unsafe-inline' https:`,
            env.STYLE_NONCE === 'true' ? `style-src 'self' 'nonce-${nonce}'` : "style-src 'self' 'unsafe-inline'",
            `object-src 'none'`,
            "base-uri 'none'",
            "upgrade-insecure-requests"
        ];

        const cspHeader = cspDirectives.join('; ');
        modifiedResponse.headers.set(`Content-Security-Policy${cspMode}`, cspHeader);

        return modifiedResponse;
    }

    // For non-HTML responses, return the original response
    return response;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		return handleRequest(request, env);
	},
} satisfies ExportedHandler<Env>;
