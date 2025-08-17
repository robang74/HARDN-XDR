/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  basePath: process.env.NODE_ENV === 'production' ? '/HARDN-XDR' : '',
  assetPrefix: process.env.NODE_ENV === 'production' ? '/HARDN-XDR/' : '',
  distDir: 'out',
  experimental: {
    outputStandalone: false
  }
}

module.exports = nextConfig
