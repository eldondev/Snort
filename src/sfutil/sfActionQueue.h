#ifndef _SF_ACTION_QUEUE_
#define _SF_ACTION_QUEUE_

#include "mempool.h"

typedef struct 
{
    MemPool mempool;

} tSfActionQueue;

typedef tSfActionQueue* tSfActionQueueId;

typedef struct _sfActionNode
{
    void (*callback)(void *);
    void  *data;

} tSfActionNode;

tSfActionQueueId sfActionQueueInit(
        int queueLength
        );
int sfActionQueueAdd(
        tSfActionQueueId actionQ, 
        void (*callback)(void *), 
        void *data
        );
void sfActionQueueExecAll(
        tSfActionQueueId actionQ
        );
void sfActionQueueExec(
        tSfActionQueueId actionQ
        );
void sfActionQueueDestroy(
        tSfActionQueueId actionQ
        );

#endif
