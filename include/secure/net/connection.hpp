#pragma once

namespace secure {

class Connection {
public:
    virtual ~Connection() = default;

    virtual void start() = 0;

    virtual void drain() = 0;

    virtual void stop() = 0;
};

}  // namespace secure
