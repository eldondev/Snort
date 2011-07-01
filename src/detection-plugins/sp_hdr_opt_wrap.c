/* Necessary hash/wrapper functions to put a .so rule's HdrOptCheck option
 * directly on the rule option tree. */

#include "sp_hdr_opt_wrap.h"
#include "sf_engine/sf_snort_plugin_api.h"

//extern int checkHdrOpt(void *p, HdrOptCheck *optData);

uint32_t HdrOptCheckHash(void *d)
{
    uint32_t a, b, c;
    HdrOptCheck *hdrData = (HdrOptCheck *)d;

    a = (uint32_t)hdrData->hdrField;
    b = hdrData->op;
    c = hdrData->value;
    mix(a,b,c);

    a += hdrData->mask_value;
    b += hdrData->flags;
    final(a,b,c);

    return c;
}

int HdrOptCheckCompare(void *l, void *r)
{
    HdrOptCheck *left = (HdrOptCheck *)l;
    HdrOptCheck *right = (HdrOptCheck *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->hdrField == right->hdrField) &&
        (left->op == right->op) &&
        (left->value == right->value) &&
        (left->mask_value == right->mask_value) &&
        (left->flags == right->flags))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}

/* This function is a wrapper to call the check function normally used in
 * .so rules */
int HdrOptEval(void *option_data, Packet *p)
{
   HdrOptCheck *hdrData = (HdrOptCheck *)option_data;

   return checkHdrOpt(p, hdrData);
}
