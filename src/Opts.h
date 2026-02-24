#pragma once

class Opts {
public:
    static Opts *get_instance();
    bool has_extra_vb() const;
};
