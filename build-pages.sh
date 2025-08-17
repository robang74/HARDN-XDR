#!/bin/bash
# Build script for GitHub Pages deployment
# This ensures proper configuration for GitHub Pages

echo "🔧 Building HARDN-XDR GitHub Pages site..."

# Run Next.js build
npm run build

# Ensure .nojekyll file exists for GitHub Pages
echo "📄 Creating .nojekyll file for GitHub Pages..."
echo "# Disable Jekyll processing for GitHub Pages" > docs/.nojekyll

# Clean up server-side files that shouldn't be in static export
echo "🧹 Cleaning up server-side files..."
rm -rf docs/server docs/cache docs/*.json docs/static/development 2>/dev/null || true

echo "✅ GitHub Pages build complete!"
echo "📁 Static files are ready in the /docs directory"
echo "🌐 Site will be available at: https://opensource-for-freedom.github.io/HARDN-XDR/"