//
// Created by paradaimu on 7/29/20.
//

#ifndef HMACWRAPER_MEXCEPTIONS_H
#define HMACWRAPER_MEXCEPTIONS_H

#include <stdexcept>
#include <sstream>

#define THROW_EXCEPTION(_str) {                          \
    std::stringstream _ss;                                        \
    _ss << "\tExplanation: " << _str << "\n    at " << __FILE__          \
        << ":" << __LINE__;                                             \
    throw std::runtime_error(_ss.str());                     \
}

#define DOC(_func)                                                       \
{                                                                       \
    try {                                                               \
        _func;                                                          \
    } catch (std::exception &ex) {                                      \
        THROW_EXCEPTION(ex.what());                \
    } catch(...) {                                                      \
        THROW_EXCEPTION("Unknown exception occured"); \
    } \
}

#endif //HMACWRAPER_MEXCEPTIONS_H
