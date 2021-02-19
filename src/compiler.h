/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SIMPLE_TUN_COMPILER_H
#define SIMPLE_TUN_COMPILER_H

#ifndef likely
#define likely(x) __builtin_expect(!!(x),1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!(x),0)
#endif
#endif //SIMPLE_TUN_COMPILER_H
