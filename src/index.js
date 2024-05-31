addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const clientId = CLIENT_ID;
const clientSecret = CLIENT_SECRET;
const baseurl = BASEURL;
const redirectUri = BASEURL + '/callback';

async function handleRequest(request) {
  const url = new URL(request.url);
  
  if (url.pathname === '/') {
      return new Response(html(), { headers: { 'content-type': 'text/html' } });
  } else if (url.pathname === '/authorize') {
      return startAuth();
  } else if (url.pathname === '/callback') {
      return handleOAuthCallback(url);
  } else if (url.pathname === '/token') {
      return getAccessToken();
  } else if (url.pathname === '/list-documents') {
      return listDocuments();
  } else if (url.pathname === '/download-document') {
      return downloadDocument(url);
  }

  return new Response('Not found', { status: 404 });
}

function generateRandomString(length) {
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(36)).substr(-2)).join('').substr(0, length);
}

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function startAuth() {
  const codeVerifier = generateRandomString(128);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomString(16);

  await OAUTH_EX.put('code_verifier', codeVerifier);
  await OAUTH_EX.put('oauth_state', state);

  const authUrl = `https://digilocker.meripehchaan.gov.in/public/oauth2/1/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=files.issueddocs&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  return Response.redirect(authUrl, 302);
}

async function handleOAuthCallback(url) {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const savedState = await OAUTH_EX.get('oauth_state');
  const codeVerifier = await OAUTH_EX.get('code_verifier');

  if (state !== savedState) {
      return new Response('Invalid state', { status: 400 });
  }

  const tokenResponse = await fetch('https://digilocker.meripehchaan.gov.in/public/oauth2/1/token', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
          code: code,
          grant_type: 'authorization_code',
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier
      })
  });

  if (!tokenResponse.ok) {
      return new Response('Failed to exchange token', { status: 500 });
  }

  const tokenData = await tokenResponse.json();
  await OAUTH_EX.put('access_token', tokenData.access_token);

  return Response.redirect(baseurl, 302);
}

async function getAccessToken() {
  const accessToken = await OAUTH_EX.get('access_token');
  if (!accessToken) {
      return new Response('Access token not found', { status: 404 });
  }

  return new Response(accessToken, { status: 200 });
}

async function listDocuments() {
  const accessToken = await OAUTH_EX.get('access_token');
  if (!accessToken) {
      return new Response('Not authorized', { status: 401 });
  }

  const documentsResponse = await fetch('https://digilocker.meripehchaan.gov.in/public/oauth2/2/files/issued', {
      headers: {
          'Authorization': `Bearer ${accessToken}`
      }
  });

  if (!documentsResponse.ok) {
      return new Response('Failed to list documents', { status: 500 });
  }

  const documents = await documentsResponse.json();
  return new Response(JSON.stringify(documents), { status: 200 });
}

async function downloadDocument(url) {
  const accessToken = await OAUTH_EX.get('access_token');
  const documentUri = url.searchParams.get('uri');

  if (!accessToken) {
      return new Response('Not authorized', { status: 401 });
  }

  const fileResponse = await fetch(`https://digilocker.meripehchaan.gov.in/public/oauth2/1/file/${documentUri}`, {
      headers: {
          'Authorization': `Bearer ${accessToken}`
      }
  });

  if (!fileResponse.ok) {
      return new Response('Failed to download document', { status: 500 });
  }

  const blob = await fileResponse.blob();
  return new Response(blob, {
      headers: {
          'Content-Disposition': 'attachment; filename=document.pdf',
          'Content-Type': 'application/pdf'
      }
  });
}

function html() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare Worker OAuth Flow</title>
  <style>
    .download-link {display: block;}
  </style>
</head>
<body>
  <button id="authorize-btn">Attach using digilocker</button>
  <!--<button id="get-token-btn">Get Access Token</button>
  <button id="list-documents-btn">List Documents</button>
  <button id="download-document-btn">Download Document</button>-->

  <ul id="document-list"></ul>

  <script>
      const workerUrl = window.location.origin;
      const downloadUrl = 'https://digilocker.meripehchaan.gov.in/public/oauth2/1/file/'
      let childWindow = null
      var timer = null; 
      document.getElementById('authorize-btn').addEventListener('click', startAuth);
      // document.getElementById('get-token-btn').addEventListener('click', getAccessToken);
      // document.getElementById('list-documents-btn').addEventListener('click', listDocuments);
      // document.getElementById('download-document-btn').addEventListener('click', downloadDocument);

      function startAuth() {
        childWindow = window.open(\`\${workerUrl}/authorize\`, 'oauth', 'width=500,height=600,popup=yes');
        timer = setInterval(checkChild, 500);
      }

      async function checkChild() {
            if (childWindow && childWindow.closed) {
                await listDocuments();
                childWindow=null;
                timer=null;
                clearInterval(timer);
            }
        }

      window.addEventListener('message', event => {
            if (event.data.type === 'auth') {
                localStorage.setItem('accessToken', event.data.accessToken);
                console.log('Access token retrieved');
                const documentListDiv = document.getElementById('document-list');
                documentListDiv.innerHTML = '';

                event.data.documents.forEach(doc => {
                    const docItem = document.createElement('div');
                    docItem.textContent = \`Document: \${doc.name} - \${doc.uri}\`;
                    documentListDiv.appendChild(docItem);
                });
            }
        });

      async function getAccessToken() {
          const response = await fetch(\`\${workerUrl}/token\`);
          if (!response.ok) {
              console.error('Failed to get access token');
              return;
          }
          const accessToken = await response.text();
          localStorage.setItem('accessToken', accessToken);
          console.log('Access token retrieved');
      }

      async function listDocuments() {
          const accessToken = localStorage.getItem('accessToken');

          if (!accessToken) {
              console.error('Not authorized');
              return;
          }

          const documentsResponse = await fetch(\`\${workerUrl}/list-documents\`);
          if (!documentsResponse.ok) {
              console.error('Failed to list documents');
              return;
          }

          const documents = await documentsResponse.json();
          const documentListDiv = document.getElementById('document-list');
          documentListDiv.innerHTML = '';

          if (documents) {
            documents.items.forEach(doc => {
                let link = document.createElement('a');
                let list = document.createElement('li');
                link.href='#0';
                link.textContent = \`\${doc.name}\`;
                link.addEventListener('click', function(event) {
                    event.preventDefault();
                    downloadDocument(\`\${doc.uri}\`);
                })
                list.appendChild(link);
                documentListDiv.appendChild(list);
            });
          }
      }

      async function downloadDocument(documentUri) {
          const accessToken = localStorage.getItem('accessToken');
        //   const documentUri = documentUri;

          if (!accessToken) {
              console.error('Not authorized');
              return;
          }

          const fileResponse = await fetch(\`\${workerUrl}/download-document?uri=\${encodeURIComponent(documentUri)}\`);
          if (!fileResponse.ok) {
              console.error('Failed to download document');
              return;
          }

          const blob = await fileResponse.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'document.pdf';
          document.body.appendChild(a);
          a.click();
          a.remove();
      }
  </script>
</body>
</html>`;
}
