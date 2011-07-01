/* Necessary hash/wrapper functions to put a .so rule's HdrOptCheck option
 * directly on the rule option tree. */

#ifndef __SP_HDR_OPT_WRAP_H__
#define __SP_HDR_OPT_WRAP_H__

#include "sf_engine/sf_snort_plugin_api.h"
#include "sfhashfcn.h"
#include "detection_options.h"

uint32_t HdrOptCheckHash(void *d);
int HdrOptCheckCompare(void *l, void *r);
int HdrOptEval(void *option_data, Packet *p);

#endif /* __SP_HDR_OPT_WRAP_H__ */
