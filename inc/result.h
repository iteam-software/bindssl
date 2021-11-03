#ifndef RESULT_H
#define RESULT_H

#include <tuple>

namespace bindssl
{

template<typename Ty>
using Result = std::tuple<Ty, bool>;

}

#endif