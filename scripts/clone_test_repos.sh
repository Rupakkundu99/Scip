#!/usr/bin/env bash
cd "$(dirname "$0")/../test_repos" || exit 1
git clone https://github.com/adeyosemanputra/pygoat.git
git clone https://github.com/fportantier/vulpy.git
echo "Done. Also add 2-3 older Flask/Django repos with pinned requirements.txt manually."
