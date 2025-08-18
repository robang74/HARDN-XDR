// next.config.js

const nextConfig = {
  output: 'export',            
  images: { unoptimized: true },
  eslint: { ignoreDuringBuilds: true } // optional: keep CI green

};
module.exports = nextConfig;
