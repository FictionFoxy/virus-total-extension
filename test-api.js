// Simple test script for the VirusTotal API
// Make sure to start the server first: pnpm run start:dev
// Then run: node test-api.js

const testUrl = 'https://example.com';
const apiEndpoint = 'http://localhost:3000/api/virustotal/scan';

async function testVirusTotalAPI() {
  console.log('🧪 Testing VirusTotal API...');
  console.log(`📡 Scanning URL: ${testUrl}`);
  
  try {
    const response = await fetch(apiEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: testUrl
      })
    });
    
    const result = await response.json();
    
    if (response.ok) {
      console.log('✅ API Response:');
      console.log(JSON.stringify(result, null, 2));
      
      if (result.data) {
        const { safe, url, last_analysis_stats } = result.data;
        console.log(`\n🔍 Scan Result for ${url}:`);
        console.log(`   Status: ${safe ? '✅ SAFE' : '❌ UNSAFE'}`);
        console.log(`   Harmless: ${last_analysis_stats.harmless}`);
        console.log(`   Malicious: ${last_analysis_stats.malicious}`);
        console.log(`   Suspicious: ${last_analysis_stats.suspicious}`);
        console.log(`   Undetected: ${last_analysis_stats.undetected}`);
      }
    } else {
      console.error('❌ API Error:');
      console.error(JSON.stringify(result, null, 2));
    }
  } catch (error) {
    console.error('❌ Network Error:', error.message);
    console.log('\n💡 Make sure the server is running: pnpm run start:dev');
  }
}

testVirusTotalAPI();
