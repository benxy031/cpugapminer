/*
 * Copyright (C) 2026  cpugapminer contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

class Opts {
public:
    static Opts *get_instance();
    bool has_extra_vb() const;
};
