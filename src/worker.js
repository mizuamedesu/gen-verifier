class PKCEGenerator {
  base64URLEncode(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  async generateRandomBytes(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return array;
  }

  async generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return this.base64URLEncode(hash);
  }

  async generatePKCEPair() {
    const randomBytes = await this.generateRandomBytes(32);
    const verifier = this.base64URLEncode(randomBytes);
    const challenge = await this.generateCodeChallenge(verifier);
    
    return {
      code_verifier: verifier,
      code_challenge: challenge,
      timestamp: Date.now()
    };
  }
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: corsHeaders
      });
    }

    // GETリクエストのみ受け付け
    if (request.method !== 'GET') {
      return new Response('Method not allowed', {
        status: 405,
        headers: {
          ...corsHeaders,
          'Content-Type': 'text/plain'
        }
      });
    }

    try {
      const generator = new PKCEGenerator();
      const pkceData = await generator.generatePKCEPair();

      return new Response(JSON.stringify(pkceData), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json'
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'Failed to generate PKCE pair',
        message: error.message
      }), {
        status: 500,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json'
        }
      });
    }
  },
};