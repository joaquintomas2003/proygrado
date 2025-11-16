#!/usr/bin/env bash
set -euo pipefail

# Colors
GREEN="\e[32m"
NC="\e[0m"

echo -e "${GREEN}==> Step 1: Entering sink/ and running p4 build + design-load${NC}"
(
  cd sink || { echo "sink/ directory not found"; exit 1; }
  ../bin/p4 build
  ../bin/p4 design-load
)

echo -e "${GREEN}==> Step 2: Restarting host services with sudo make restart${NC}"
(
  cd host || { echo "host/ directory not found"; exit 1; }
  sudo make restart
)

echo -e "${GREEN}==> Step 3: Running DPDK binding and MoonGen hugepages setup${NC}"
(
  ./bin/dpdk_bind_if vf0_0
  sudo ~/MoonGen/setup-hugetlbfs.sh
)

echo -e "${GREEN}All steps completed successfully!${NC}"
