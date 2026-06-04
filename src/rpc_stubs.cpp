/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Rpc.h"
#include "Opts.h"

BlockHeader::BlockHeader(const std::string *s) {
    if (s) hex = *s; else hex = std::string();
    target = 0;
}

std::string BlockHeader::get_hex() const { return hex; }

// Minimal Opts stubs
Opts *Opts::get_instance() { return nullptr; }
bool Opts::has_extra_vb() const { return false; }
