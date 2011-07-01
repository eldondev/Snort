/*
 * sf_decompression.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2011 Sourcefire, Inc.
 *
 * Author: Ryan Jordan
 *
 * Date: 3/8/2011
 *
 * Implementation of Decompression API for Snort Plugins.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef DECOMPRESS_UNIT_TEST
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

#include "sf_decompression.h"
#else
#include <zlib.h>

#include "sf_snort_plugin_api.h"
#include "sf_decompression.h"
#endif /* DECOMPRESS_UNIT_TEST */

/* Implementation-Specific Defines */
#define DEFLATE_WBITS -15
#define ZLIB_WBITS 47

/* Decompression state is defined here so that
   dynamic plugins don't access it directly. */
typedef struct decompress_state
{
    compression_type_t type;
    uint32_t flags;
    void *lib_info;
    int lib_return;
} decompress_state_t;

/* Decompression state flags */
#define SNORT_ZLIB_INIT_NEEDED 0x00000001

/* Zlib-specific init function */
static inline decompress_state_t * SnortDecompressInitZlib(compression_type_t type)
{
    decompress_state_t *state = calloc(1, sizeof(decompress_state_t) );
    z_stream *zlib_stream     = calloc(1, sizeof(z_stream) );

    if (state == NULL || zlib_stream == NULL)
        DynamicEngineFatalMessage("Unable to allocate memory in SnortDecompressInitZlib()\n");

    /* Setup Zlib memory management callbacks */
    zlib_stream->zalloc = NULL;
    zlib_stream->zfree = NULL;
    zlib_stream->opaque = NULL;

    /* Fill out state object */
    state->type = type;
    state->lib_info = (void *) zlib_stream;

    /* Can't call inflateInit() until there's some data */
    state->flags |= SNORT_ZLIB_INIT_NEEDED;

    return state;
}

/* Zlib-specific Destroy function */
static inline int SnortDecompressDestroyZlib(decompress_state_t *state)
{
    z_streamp zlib_stream = (z_streamp) state->lib_info;
    int ret;

    if (zlib_stream == NULL)
        return SNORT_DECOMPRESS_BAD_ARGUMENT;

    ret = inflateEnd(zlib_stream);

    free(zlib_stream);
    free(state);

    if (ret == Z_OK)
        return SNORT_DECOMPRESS_OK;

    /* XXX: Only other possibility is Z_STREAM_ERROR.
            Can't set state->lib_ret because we just freed the state. */
    return SNORT_DECOMPRESS_ERROR;
}

/* Zlib-specific Decompression function. */
static inline int SnortDecompressZlib(decompress_state_t *state, uint8_t *input, uint32_t input_len,
                               uint8_t *output, uint32_t output_bufsize, uint32_t *output_len)
{
    z_streamp zlib_stream = (z_streamp) state->lib_info;
    int zlib_ret;
    int snort_ret = SNORT_DECOMPRESS_OK;

    if (zlib_stream == NULL)
        return SNORT_DECOMPRESS_BAD_ARGUMENT; // Uninitialized state object.

    /* The call to inflateInit() requires some data to be provided.
       That's why the call isn't done in SnortDecompressInit(). */
    if (state->flags & SNORT_ZLIB_INIT_NEEDED)
    {
        if (input == NULL)
            return SNORT_DECOMPRESS_BAD_ARGUMENT;

        zlib_stream->next_in = input;
        zlib_stream->avail_in = input_len;

        /* Zlib init has a funky parameter for window size.
           ZLIB_WBITS specifies that we'll inflate both Zlib & Gzip streams.
           DEFLATE_WBITS is needed for raw deflate streams w/o headers
           (as seen in HTTP). */
        if (state->type == COMPRESSION_TYPE_DEFLATE)
            zlib_ret = inflateInit2(zlib_stream, DEFLATE_WBITS);
        else
            zlib_ret = inflateInit2(zlib_stream, ZLIB_WBITS);
        state->lib_return = zlib_ret;

        state->flags &= ~SNORT_ZLIB_INIT_NEEDED;
    }
    /* If input is NULL, just continue decompressing from the last spot.
       This is how a caller would handle truncated output. */
    else if (input)
    {
        zlib_stream->next_in = input;
        zlib_stream->avail_in = input_len;
    }
        
    zlib_stream->next_out = output;
    zlib_stream->avail_out = output_bufsize;
    
    while (zlib_stream->avail_in > 0 && zlib_stream->avail_out > 0)
    {
        zlib_ret = inflate(zlib_stream, Z_SYNC_FLUSH);
        state->lib_return = zlib_ret;

        if (zlib_ret == Z_STREAM_END)
            break; // Not an error, just hit the end of compressed data.

        if (zlib_ret != Z_OK)
        {
            snort_ret = SNORT_DECOMPRESS_BAD_DATA;
            break;
        }
    }

    if ((zlib_stream->avail_in > 0 && zlib_stream->avail_out == 0) &&
        (snort_ret != SNORT_DECOMPRESS_BAD_DATA))
    {
        snort_ret = SNORT_DECOMPRESS_OUTPUT_TRUNC;
    }

    *output_len = output_bufsize - zlib_stream->avail_out;

    return snort_ret;
}

/* This function initializes a Decompression API state object.
   It must be called first when using decompression.

   Arguments: type => Type of decompression to use (gzip, deflate)
   Returns: void pointer to decompression state object
*/
ENGINE_LINKAGE void * SnortDecompressInit(compression_type_t type)
{
    decompress_state_t *state = NULL;

    switch (type)
    {
        case COMPRESSION_TYPE_ZLIB:
        case COMPRESSION_TYPE_DEFLATE:
            state = SnortDecompressInitZlib(type);
            break;
        case COMPRESSION_TYPE_MAX:
        default:
            /* invalid type... */
            return NULL;
    }

    return (void *) state;
}

/* This function destroys a Decompression API state object.

   Arguments: void *s => state object allocated by SnortDecompressInit().
   Returns: SNORT_DECOMPRESS_OK on success, negative on error.
*/
ENGINE_LINKAGE int SnortDecompressDestroy(void *s)
{
    decompress_state_t *state = s;

    if (state == NULL)
        return SNORT_DECOMPRESS_BAD_ARGUMENT;

    switch (state->type)
    {
        case COMPRESSION_TYPE_ZLIB:
        case COMPRESSION_TYPE_DEFLATE:
            return SnortDecompressDestroyZlib(state);
        case COMPRESSION_TYPE_MAX:
        default:
            break;
    }

    /* Bad type. Was this constructed outside of SnortDecompressInit()? */
    return SNORT_DECOMPRESS_BAD_ARGUMENT;
}

/* This is the function that decompresses data.

   Arguments:
     void *state             => pointer to state object allocated by SnortDecompressInit().
     uint8_t *input          => pointer to buffer that stores compressed data.
                                pass NULL to continue decompressing the previous input.
     uint32_t input_len      => length of input to decompress.
                                ignored if "input" is set to NULL.
     uint8_t *output         => pointer to buffer where decompressed output will be stored.
     uint32_t output_bufsize => available space in output buffer.
     uint32_t *output_len    => gets set to the actual amount of output generated.
   Returns:
     SNORT_DECOMPRESS_OK: success
     SNORT_DECOMPRESS_BAD_ARGUMENT: Bad arguments passed in. Could be null pointers,
                                    uninitialized state objects.
     SNORT_DECOMPRESS_BAD_DATA:     Error decompressing the data. Could be corrupted
                                    input, or the wrong compression type was set.
     SNORT_DECOMPRESS_OUTPUT_TRUNC: Decompression was successful, but the output
                                    buffer filled up. Call SnortDecompress() again
                                    with NULL input after consuming the output.
*/
ENGINE_LINKAGE int SnortDecompress(void *state, uint8_t *input, uint32_t input_len,
                    uint8_t *output, uint32_t output_bufsize, uint32_t *output_len)
{
    decompress_state_t *internal_state;

    /* NULL "input" ptr is OK, it signals that we should continue decompressing the
       last input. The caller should have consumed output and made more space. */
    if (state == NULL || output == NULL || output_len == NULL)
        return SNORT_DECOMPRESS_BAD_ARGUMENT;

    internal_state = (decompress_state_t *) state;

    switch (internal_state->type)
    {
        case COMPRESSION_TYPE_ZLIB:
        case COMPRESSION_TYPE_DEFLATE:
            return SnortDecompressZlib(internal_state, input, input_len,
                                       output, output_bufsize, output_len);
        case COMPRESSION_TYPE_MAX:
        default:
            break;
    }

    return SNORT_DECOMPRESS_BAD_ARGUMENT;
}



/* This section is a unit test meant to independently test the Decompression API.
   Compile like so:
   gcc -DDECOMPRESS_UNIT_TEST sf_decompression.c -o decompression_unit_test -lz
 */
#ifdef DECOMPRESS_UNIT_TEST
/* Driver program uses the Snort decompression API to read from a file and
   spew decompressed data to stdout. */
int main (int argc, char *argv[])
{   
    FILE *input;
    void *zlib_state;

    uint8_t input_buffer[1024];
    uint8_t output_buffer[1024];
    size_t bytes_read;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        exit(-1);
    }

    input = fopen(argv[1], "r");

    /* Step 1: Init */
    zlib_state = SnortDecompressInit( COMPRESSION_TYPE_ZLIB );
    if (zlib_state == NULL)
    {
        fprintf(stderr, "Some bad stuff happened and SnortInit() returned NULL.\n");
        exit(-1);
    }

    /* Step 2: Iterate over your input and call SnortDecompress */
    bytes_read = fread(input_buffer, 1, sizeof(input_buffer), input);
    while (bytes_read > 0)
    {
        uint32_t output_bufsize = sizeof(output_buffer);
        uint32_t output_len;
        int ret;

        ret = SnortDecompress(zlib_state, input_buffer, bytes_read,
                              output_buffer, output_bufsize, &output_len);

        fwrite(output_buffer, 1, output_len, stdout);

        while (ret == SNORT_DECOMPRESS_OUTPUT_TRUNC)
        {
            /* Subsequent calls use NULL to signify that we want to continue
               decompressing the last input. */
            ret = SnortDecompress(zlib_state, NULL, 0, output_buffer, output_bufsize, &output_len);
            fwrite(output_buffer, 1, output_len, stdout);
        }

        /* Handle your return codes */
        switch(ret)
        {
            case SNORT_DECOMPRESS_BAD_DATA:
                fprintf(stderr, "SnortDecompress() returned BAD_DATA!\n");
                break;
            case SNORT_DECOMPRESS_BAD_ARGUMENT:
                fprintf(stderr, "SnortDecompress() returned BAD_ARGUMENT!\n");
                break;
        }

        /* Get more data! */
        bytes_read = fread(input_buffer, 1, sizeof(input_buffer), input);
    }

    /* Step 3: Destroy! */
    SnortDecompressDestroy(zlib_state);
    fclose(input);

    return 0;
}

#endif /* DECOMPRESS_UNIT_TEST */
