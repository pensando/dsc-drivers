#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# SPDX-FileCopyrightText: Copyright (C) 2024 Advanced Micro Devices, Inc.

# Source this file to handle OracleLinux UEK versions that are
# built with a later version of gcc to its distribution default.

command -v rpm >/dev/null && kernel_package=$(rpm -q --whatprovides "$(realpath "$PWD")")
if [ -n "$kernel_package" ]; then
  toolset=$(rpm -q --requires "$kernel_package" | grep -Eo "^gcc-toolset-[0-9]+" | head -1)
  if [ -f "/opt/rh/$toolset/enable" ]; then
    # shellcheck source=/dev/null
    . "/opt/rh/$toolset/enable"
    echo "Sourced $toolset (required by RPM $kernel_package): $(gcc --version | head -1)"
  fi
fi
