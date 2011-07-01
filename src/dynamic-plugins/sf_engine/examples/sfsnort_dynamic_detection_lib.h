#ifndef SFSNORT_DYNAMIC_DETECTION_LIB_H_
#define SFSNORT_DYNAMIC_DETECTION_LIB_H_

#ifdef WIN32
#ifdef SF_SNORT_DETECTION_DLL
#define DETECTION_LINKAGE __declspec(dllexport)
#else
#define DETECTION_LINKAGE __declspec(dllimport)
#endif
#else /* WIN32 */
#define DETECTION_LINKAGE
#endif /* WIN32 */

#endif /* SFSNORT_DYNAMIC_DETECTION_LIB_H_ */

