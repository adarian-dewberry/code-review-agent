#!/usr/bin/env node
/**
 * Node.js/JavaScript client for Frankie Code Review API
 * 
 * Usage:
 *   node frankie-client.js /path/to/file.js
 *   cat vulnerable.js | node frankie-client.js
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const FRANKIE_API_URL = process.env.FRANKIE_URL || 'http://localhost:7860';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

async function reviewCode(code, filename = 'code.js') {
    // Option 1: Use local API endpoint (if Gradio app exposes API)
    try {
        const response = await fetch(`${FRANKIE_API_URL}/api/review`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                data: [
                    code,
                    true,  // security checks
                    true,  // compliance checks
                    false, // logic checks
                    false, // performance checks
                    filename
                ]
            })
        });

        if (!response.ok) {
            throw new Error(`API error: ${response.statusText}`);
        }

        const result = await response.json();
        return result;
    } catch (err) {
        console.error('❌ API call failed:', err.message);
        console.log('\n💡 Make sure Frankie is running: docker-compose up');
        process.exit(1);
    }
}

async function main() {
    let code = '';
    let filename = 'stdin.js';

    // Check if file path provided as argument
    if (process.argv.length > 2) {
        const filePath = process.argv[2];
        if (!fs.existsSync(filePath)) {
            console.error(`❌ File not found: ${filePath}`);
            process.exit(1);
        }
        code = fs.readFileSync(filePath, 'utf-8');
        filename = path.basename(filePath);
    } else {
        // Read from stdin
        const chunks = [];
        for await (const chunk of process.stdin) {
            chunks.push(chunk);
        }
        code = Buffer.concat(chunks).toString('utf-8');
    }

    if (!code.trim()) {
        console.error('❌ No code provided');
        process.exit(1);
    }

    console.log(`🐕 Frankie is reviewing ${filename}...`);
    console.log('---');

    const result = await reviewCode(code, filename);

    // Pretty print results
    console.log(JSON.stringify(result, null, 2));
}

main().catch(err => {
    console.error('❌ Error:', err);
    process.exit(1);
});
