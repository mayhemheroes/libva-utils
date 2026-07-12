#include <stddef.h>
#include <stdint.h>

#include "tinyjpeg.h"

extern "C" struct jdec_private *tinyjpeg_init(void);
extern "C" void tinyjpeg_free(struct jdec_private *priv);
extern "C" int tinyjpeg_parse_header(struct jdec_private *priv,
                                     const unsigned char *buf, unsigned int size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // tinyjpeg_parse_header unconditionally reads buf[0] and buf[1] before it
    // consults `size`, so feed it at least the two bytes it always touches.
    if (size < 2)
        return 0;

    struct jdec_private *jdec = tinyjpeg_init();
    if (jdec == NULL)
        return 0;

    // Drive the real parser over the whole input and its true length so the
    // fuzzer explores the full marker-parsing state machine (the upstream
    // parser trusts the embedded chunk lengths and can over-read the buffer).
    tinyjpeg_parse_header(jdec, data, (unsigned int)size);

    tinyjpeg_free(jdec);
    return 0;
}
