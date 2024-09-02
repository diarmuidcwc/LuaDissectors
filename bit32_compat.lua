-- bit32_compat.lua
local bit32 = {}

function bit32.band(a, b)
    return a & b
end

function bit32.bor(a, b)
    return a | b
end

function bit32.bxor(a, b)
    return a ~ b
end

function bit32.bnot(a)
    return ~a
end

function bit32.lshift(a, b)
    return a << b
end

function bit32.rshift(a, b)
    return a >> b
end

function bit32.arshift(a, b)
    return (a >> b) | ((a < 0 and ((1 << b) - 1) << (32 - b)) or 0)
end

function bit32.extract(a, field, width)
    width = width or 1
    return (a >> field) & ((1 << width) - 1)
end

function bit32.replace(a, value, field, width)
    width = width or 1
    local mask = ((1 << width) - 1) << field
    return (a & ~mask) | ((value << field) & mask)
end

return bit32
