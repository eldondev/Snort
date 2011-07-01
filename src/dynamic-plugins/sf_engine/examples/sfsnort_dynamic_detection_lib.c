
#include "sf_snort_plugin_api.h"
#include "sf_dynamic_meta.h"
#include "detection_lib_meta.h"
#include "stdio.h"
#include "string.h"
#include "sfsnort_dynamic_detection_lib.h"

extern Rule *rules[];

DETECTION_LINKAGE int InitializeDetection()
{
    return RegisterRules(rules);
}

DETECTION_LINKAGE int DumpSkeletonRules()
{
    return DumpRules(DETECTION_LIB_NAME, rules);
}


DETECTION_LINKAGE int LibVersion(DynamicPluginMeta *dpm)
{
    dpm->type  = TYPE_DETECTION;
    dpm->major = DETECTION_LIB_MAJOR;
    dpm->minor = DETECTION_LIB_MINOR;
    dpm->build = DETECTION_LIB_BUILD;
    strncpy(dpm->uniqueName, DETECTION_LIB_NAME, MAX_NAME_LEN);
    return 0;
}

DETECTION_LINKAGE int EngineVersion(DynamicPluginMeta *dpm)
{

    dpm->type  = TYPE_ENGINE;
    dpm->major = REQ_ENGINE_LIB_MAJOR;
    dpm->minor = REQ_ENGINE_LIB_MINOR;
    dpm->build = 0;
    strncpy(dpm->uniqueName, REQ_ENGINE_LIB_NAME, MAX_NAME_LEN);
    return 0;
}
