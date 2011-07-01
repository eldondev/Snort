
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "util.h"
#include "sfActionQueue.h"
#include "mempool.h"

tSfActionQueueId sfActionQueueInit(
        int queueLength
        )
{
    tSfActionQueue *queue = SnortAlloc(sizeof(tSfActionQueue));
    if (queue)
    {
        if (mempool_init(&queue->mempool,
                queueLength, sizeof(tSfActionNode)) != 0)
        {
            FatalError("%s(%d) Could not initialize action queue memory pool.\n",
                    __FILE__, __LINE__);
        }
    }

    return queue;
}

int sfActionQueueAdd(
        tSfActionQueueId actionQ, 
        void (*callback)(void *), 
        void *data
        )
{
    MemBucket *bucket = mempool_alloc(&actionQ->mempool);

    if (bucket != NULL)
    {
        tSfActionNode *node = bucket->data;
        node->callback = callback;
        node->data = data;

        //Using used_list in mempool for tracking allocated MemBucket
        return 0;
    }

    ErrorMessage("Could not queue decoder action\n");
    return -1;
}

void sfActionQueueExecAll(
        tSfActionQueueId actionQ
        )
{
    //drain
    while (mempool_numUsedBucket(&actionQ->mempool))
    {
        sfActionQueueExec(actionQ);
    }
}

void sfActionQueueExec(
        tSfActionQueueId actionQ
        )
{

    MemBucket *firstUsedBucket = mempool_oldestUsedBucket(&actionQ->mempool);

    if (firstUsedBucket)
    {
        tSfActionNode *node = (tSfActionNode *)firstUsedBucket->data;
        (node->callback)(node->data);
        mempool_free(&actionQ->mempool, firstUsedBucket);
    }
}

/**Destroys action queue. All memory allocated by the actionQueue module is 
 * freed. Since the queued actions are not executed, any memory freed in the action
 * will be lost. User should do a execAll if there is a potential memory leak
 * or the actions must be completed.
 */
void sfActionQueueDestroy(
        tSfActionQueueId actionQ
        )
{
    mempool_destroy(&actionQ->mempool);
    free(actionQ);
}


