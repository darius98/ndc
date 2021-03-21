#ifndef NDC_UTILS_CONFIG_H_
#define NDC_UTILS_CONFIG_H_

#ifdef __cplusplus
    #define NDC_BEGIN_DECLS extern "C" {
    #define NDC_END_DECLS }
#else
    #define NDC_BEGIN_DECLS
    #define NDC_END_DECLS
#endif

#ifdef __has_attribute
    #if __has_attribute(unused)
        #define UNUSED __attribute__((__unused__))
    #else
        #define UNUSED
    #endif
#else
    #define UNUSED
#endif

#endif
