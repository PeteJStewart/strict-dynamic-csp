# CSP Nonce Cloudflare Worker

This Cloudflare Worker automatically injects Content Security Policy (CSP) headers with dynamic nonces into HTML responses, helping to secure your website against XSS attacks.

## Features

- Automatically injects CSP headers with secure nonces
- Adds nonce attributes to all script tags
- Supports both enforcement and report-only modes
- Uses `strict-dynamic` for enhanced security
- Compatible with modern browsers
- Zero performance impact - uses Cloudflare's HTMLRewriter for efficient streaming transformations
- No blocking or render delays - nonces are injected on-the-fly without buffering content

## Installation

1. Clone this repository:
```bash
git clone https://github.com/your-username/csp-nonce-worker.git
cd csp-nonce-worker
```

2. Install [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/), Cloudflare's CLI tool: 
```bash
npm install -g @cloudflare/wrangler
```

3. Login to your Cloudflare account:
```bash
wrangler login
```

4. Set up your environment variables (optional):
```bash
wrangler secret put ENFORCE_CSP
```

5. Deploy the worker:
```bash
wrangler deploy
```

### Setting Up Routes

You can configure the worker to run on specific routes in your Cloudflare dashboard:

1. Go to your domain in Cloudflare dashboard
2. Click "Workers Routes"
3. Click "Add Route"
4. Enter your route pattern (e.g., `example.com/*`)
5. Select your CSP worker

## Usage Guide

### Testing Phase (Recommended)

1. Start with report-only mode by setting `ENFORCE_CSP = "false"`. This will add a `Content-Security-Policy-Report-Only` header.
2. Monitor your browser's console for CSP violations.
3. Address any legitimate scripts that are being blocked.
4. Test thoroughly across different pages and functionality.

### Enforcement

Once you're confident that all legitimate scripts are working:

1. Update the environment variable: `ENFORCE_CSP = "true"`
2. Deploy the updated configuration
3. The worker will now use `Content-Security-Policy` header to enforce the policy

## Security Details

The CSP configuration includes:

- `script-src`:
  - `'strict-dynamic'`: Allows scripts loaded by trusted scripts
  - `'nonce-[random]'`: Dynamic nonce for inline scripts
  - `'unsafe-inline'`: Fallback for older browsers
  - `https:`: Fallback for browsers not supporting strict-dynamic
- `style-src`:
  - `'self'`: Allows loading stylesheets from same origin
  - `'nonce-[random]'`: Dynamic nonce for inline styles when STYLE_NONCE is enabled
- `object-src 'none'`: Prevents injection of plugins
- `base-uri 'none'`: Prevents base tag hijacking
- `upgrade-insecure-requests`: Upgrades HTTP requests to HTTPS

## Troubleshooting

Common issues you might encounter:

1. **Blocked Scripts**: Check the browser console for CSP violation reports
2. **Third-party Scripts**: Ensure they're loaded via HTTPS
3. **Inline Scripts**: All inline scripts need the nonce attribute (automatically handled by the worker)

## Development

To run locally:

```bash
wrangler dev
```

This allows you to test changes before deployment.

## Best Practices

1. Always start with report-only mode
2. Monitor CSP violations in your browser's console
3. Maintain a list of legitimate scripts that need to be allowed
4. Test thoroughly across different pages and user scenarios
5. Consider implementing CSP violation reporting to track issues

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
