/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */


// Define the Env interface for environment variables
interface Env {
    ENFORCE_CSP: string;
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

        const modifiedResponse = rewriter.transform(response);

        // Determine CSP mode based on environment variable
        const cspMode = env.ENFORCE_CSP === 'true' ? '' : '-Report-Only';
        const cspHeader = `script-src 'strict-dynamic' 'nonce-${nonce}' 'unsafe-inline'; object-src 'none'; base-uri 'none';`;

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
