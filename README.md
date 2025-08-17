# HARDN-XDR

Advanced Linux Security Hardening Platform with modern Next.js-powered GitHub Pages website.

## Website Development

This repository includes a Next.js-based GitHub Pages website with:
- **Grey Cyber Theme**: Professional stoic color scheme with cyber aesthetic
- **Interactive Terminal Demo**: Live demonstration of HARDN-XDR capabilities
- **Responsive Design**: Mobile-friendly layout using Tailwind CSS
- **TypeScript**: Type-safe development experience
- **Static Export**: Optimized for GitHub Pages deployment

### Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

### Building for GitHub Pages

Use the provided build script for GitHub Pages deployment:

```bash
# Build and prepare for GitHub Pages
./build-pages.sh
```

This script:
- Runs the Next.js build process
- Creates the required `.nojekyll` file for GitHub Pages
- Cleans up server-side files that shouldn't be in static export
- Outputs static files to the `/docs` directory

### Manual Build

Alternatively, you can build manually:

```bash
# Build the site
npm run build

# The static files will be in the /docs directory
# Remember to add .nojekyll file for GitHub Pages
echo "# Disable Jekyll processing" > docs/.nojekyll
```

### Website Features

- **DISA STIG Compliance**: Government-grade security standards
- **CIS Controls**: Industry-standard security benchmarks  
- **FIPS 140-2**: Federal cryptographic standards
- **Multi-Architecture**: AMD64 and ARM64 support
- **Real-time Monitoring**: Matrix-themed compliance dashboard
- **Automated Hardening**: 41+ security modules

### Development

The website is built with:
- [Next.js 15.4.6](https://nextjs.org) - React framework
- [Tailwind CSS 4](https://tailwindcss.com) - Utility-first CSS
- [TypeScript](https://www.typescriptlang.org) - Type safety
- Custom cyber theme with grey color palette

### Deployment

The site deploys automatically to GitHub Pages at:
🌐 https://opensource-for-freedom.github.io/HARDN-XDR/

For more details, see the [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying).
